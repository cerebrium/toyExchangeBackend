package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// dev jwt setup struct
type User struct {
	ID       uint16 `json:"_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenDetails struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	AccessUuid   string `json:"accessUuid"`
	RefreshUuid  string `json:"refreshUuid"`
	AtExpires    int64  `jdon:"atExpires"`
	RtExpires    int64  `json:"rtExpires"`
}

type AccessToken struct {
	AccessUuid string `json:"accessUuid"`
	ID         uint64 `json:"_id"`
	Expiration int64  `json:"expiration"`
}
type RefreshToken struct {
	RefreshUuid string `json:"refreshUuid"`
	ID          uint64 `json:"_id"`
	Expiration  int64  `json:"expiration"`
}

type BearToken struct {
	Authorization string `json:"authorization"`
}

type Access struct {
	AccessToken string `json:"accesstoken"`
}

type BToken struct {
	ID          uint64 `json:"_id"`
	AccessToken string `json:"accesstoken"`
}

// use godot package to load/read the .env file and
// return the value of the key
func goDotEnvVariable(key string) string {

	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	return os.Getenv(key)
}

// function for accessing the database
func GetMongoDbConnection() (*mongo.Client, error) {

	// grab the url for the database
	dotenv := goDotEnvVariable("MONGO_STRING")

	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(dotenv))

	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.Background(), readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	return client, nil
}

// function for connection to specific db and collection
func getMongoDbCollection(DbName string, CollectionName string) (*mongo.Collection, error) {

	client, err := GetMongoDbConnection()

	// handle errors
	if err != nil {
		return nil, err
	}

	collection := client.Database(DbName).Collection(CollectionName)

	return collection, nil
}

// function to create token
func CreateToken(userid uint64) (*TokenDetails, error) {

	// ----- env vars ------//
	// grab the access secret
	dotenvAcces := goDotEnvVariable("ACCESS_SECRET")

	// grab the refresh secret
	dotenvRefresh := goDotEnvVariable("REFRESH_SECRET")

	// ------- make the tokenDetails -------//

	// instantiate a pointer to the token details struct
	td := &TokenDetails{}

	// if the toek is going to expire, add another 15 minutes
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()

	// change the uuid for the new token
	td.AccessUuid = uuid.NewV4().String()

	// declaring the refresh token expiration time
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()

	// declaring the uuid for the refresh token
	td.RefreshUuid = uuid.NewV4().String()

	// create the error
	var err error

	// -------------- Creating Access Token ------------------ //

	// instantiate the struct
	atClaims := jwt.MapClaims{}

	// add the claims to the 3rd party struct
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires

	// with hsa signiture and claims
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	// create the object with the secret key to the token
	td.AccessToken, err = at.SignedString([]byte(dotenvAcces))

	// handle err
	if err != nil {
		return nil, err
	}
	// -------------- Creating Refresh Token ------------------ //
	// instantiate the struct
	rtClaims := jwt.MapClaims{}

	// add the claims to the 3rd party struct
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires

	// with hsa signiture and claims
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)

	// create the object with the secret key to the token
	td.RefreshToken, err = rt.SignedString([]byte(dotenvRefresh))

	// handle err
	if err != nil {
		return nil, err
	}
	return td, nil
}

// function for saving tokens to the db
func CreateAuth(userid uint64, td *TokenDetails) error {
	// convert unix to utc
	// at := time.Unix(td.AtExpires, 0)
	// rt := time.Unix(td.RtExpires, 0)
	// now := time.Now()

	// make the token object to store
	var mongoAccess = AccessToken{
		AccessUuid: td.AccessUuid,
		ID:         userid,
		Expiration: td.AtExpires,
	}

	var mongoRefresh = RefreshToken{
		RefreshUuid: td.RefreshUuid,
		ID:          userid,
		Expiration:  td.RtExpires,
	}

	// connect to database
	collection, err := getMongoDbCollection("toyusers", "tokens")

	// handle errors
	if err != nil {
		// retunr the error
		return err
	}

	// filter to only get one key
	filter := bson.M{
		"$or": bson.A{
			bson.M{"accessUuid": mongoAccess.AccessUuid},
			bson.M{"refreshUuid": mongoRefresh.RefreshUuid},
		},
	}

	// make the results be in the correct format
	var results []bson.M

	// find if the items exist
	cur, err := collection.Find(context.Background(), filter)
	defer cur.Close(context.Background())

	// handle errors
	if err != nil {
		return err
	}

	// grab all of the results from the query
	cur.All(context.Background(), &results)

	// if the token does not exist
	if results == nil {
		// insert the access key:value
		res, err := collection.InsertOne(context.Background(), mongoAccess)

		// handle err
		if err != nil {
			return err
		}

		// insert the refresh key:value
		resRef, err := collection.InsertOne(context.Background(), mongoRefresh)

		// handle err
		if err != nil {
			return err
		}

		res = nil
		resRef = nil

		fmt.Println("", res, resRef)
	} else {
		// check for the times

	}

	return nil
}

// check the token against the db
func CheckToken(bearToke string) bool {
	// connect to the database
	collection, err := getMongoDbCollection("toyusers", "tokens")
	if err != nil {
		fmt.Println(err.Error())
		// error in connection return error
		return false
	}
	// filter
	var filter bson.M = bson.M{}

	// make the results be in the correct format
	var results []bson.M

	// actually make the request using the cursor
	cur, err := collection.Find(context.Background(), filter, options.Find())
	defer cur.Close(context.Background())

	// handle errors
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	// grab all of the results from the quesry
	cur.All(context.Background(), &results)

	// check for matching token
	for _, token := range results {
		if token["accesstoken"] == bearToke {
			return true
		}
	}

	// handle errors
	if results == nil {
		return false
	}

	// default reject
	return false
}

func main() {
	// load the env file
	godotenv.Load()

	// instantiate fiber
	app := fiber.New()

	// allow for cors
	app.Use(cors.New())

	// Login function
	app.Post("/login", func(c *fiber.Ctx) error {
		// using the sample user
		user := new(User)

		// check if the post body matches the format
		if err := c.BodyParser(user); err != nil {
			fmt.Println("error in body parser: ", user)
			// return the error
			return c.Status(500).Send([]byte(err.Error()))
		}

		// -------------- Find the user in database ---------------- //

		// connect to the database
		collection, err := getMongoDbCollection("toyusers", "users")
		if err != nil {
			// error in connection return error
			return c.Status(500).Send([]byte(err.Error()))
		}

		// filter to find the user
		var filter bson.M = bson.M{}
		if user.Username != "" {
			// for testing purposes this is hardcoded
			username := (user.Username)
			filter = bson.M{"username": username}
		}

		// make the results be in the correct format
		var results []bson.M

		// actually make the request using the cursor
		cur, err := collection.Find(context.Background(), filter, options.Find())
		defer cur.Close(context.Background())

		// handle errors
		if err != nil {
			return c.Status(500).Send([]byte(err.Error()))
		}

		// grab all of the results from the quesry
		cur.All(context.Background(), &results)

		// handle errors
		if results == nil {
			return c.Status(404).SendString("User Not Found")
		}

		// convert data to usable json
		jsonUser, err := json.Marshal(results)

		// error handling
		if err != nil {
			// if error return it
			return c.Status(500).Send([]byte(err.Error()))
		}

		// instantiate the user class
		var mongoUser []User

		// convert json to readable format
		json.Unmarshal(jsonUser, &mongoUser)

		// get the user
		var mongoFoundUser = mongoUser[0]

		// if there is no error, compare the users
		if user.Username != mongoFoundUser.Username || user.Password != mongoFoundUser.Password {
			// if the user is not found return unauthorized
			return c.Status(401).SendString("Unauthorized User")
		}

		// -------------------  Handle Token ----------------- //

		// if the user is found make a token and return it
		token, err := CreateToken(uint64(mongoFoundUser.ID))

		// check for errors
		if err != nil {
			fmt.Println("error: ", err)
			// if error return it
			return c.Status(500).Send([]byte(err.Error()))
		}

		// save the token to db
		// connect to the database
		tcollection, err := getMongoDbCollection("toyusers", "tokens")

		if err != nil {
			fmt.Println("error line 360: ", err)
			// error in connection return error
			return c.Status(500).Send([]byte(err.Error()))
		}

		// create the token object
		tokeaccess := &Access{
			AccessToken: token.AccessToken,
		}

		// marshal into a json string
		jtoke, _ := json.Marshal(tokeaccess)

		// unmarshal it
		json.Unmarshal([]byte(jtoke), &tokeaccess)

		// insert access token
		res, err := tcollection.InsertOne(context.Background(), tokeaccess)
		if err != nil {
			return c.Status(500).Send([]byte(err.Error()))
		}

		fmt.Println("response line 379: ", res)

		// if token successfully generated return the token
		json, err := json.Marshal(token)

		// error handling
		if err != nil {
			// if error return it
			return c.Status(500).Send([]byte(err.Error()))
		}

		// return the token
		return c.Status(200).Send(json)
	})

	// get users
	app.Get("/users", func(c *fiber.Ctx) error {
		// check if the token exists
		if CheckToken(string(c.Request().Header.Peek("Authorization"))) {
			// connect to the database
			collection, err := getMongoDbCollection("toyusers", "users")
			if err != nil {
				// error in connection return error
				return c.Status(500).Send([]byte(err.Error()))
			}

			// filter
			var filter bson.M = bson.M{}

			// make the results be in the correct format
			var results []bson.M

			// actually make the request using the cursor
			cur, err := collection.Find(context.Background(), filter, options.Find())
			defer cur.Close(context.Background())

			// handle errors
			if err != nil {
				return c.Status(500).Send([]byte(err.Error()))
			}

			// grab all of the results from the quesry
			cur.All(context.Background(), &results)

			// handle errors
			if results == nil {
				return c.Status(404).SendString("not Found")
			}

			// turn the data into json
			json, err := json.Marshal(results)

			// handle errors
			if err != nil {
				return c.Status(500).Send([]byte(err.Error()))
			}

			// send the data
			return c.Send(json)
		} else {
			return c.Status(500).SendString("user not authenticated")
		}
	})

	// allow for heroku to set port
	port := ":" + os.Getenv("PORT")

	if port == "" {
		port = "5000"
	}
	app.Listen(port)
}
