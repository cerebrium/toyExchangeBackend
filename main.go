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
func CreateToken(userid uint64) (string, error) {
	var err error

	// grab the secret
	dotenv := goDotEnvVariable("ACCESS_SECRET")

	// instantiate the map
	atClaims := jwt.MapClaims{}

	// set the map values
	atClaims["authorized"] = true

	// uuid passed in
	atClaims["user_id"] = userid

	// how long until the token expires
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	// makes the configuration for the token using hsa256 and claims
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	// makes the token sighned with the access secret
	token, err := at.SignedString([]byte(dotenv))

	// handle error
	if err != nil {
		return "", err
	}

	// return the token
	return token, nil
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
			// if error return it
			return c.Status(500).Send([]byte(err.Error()))
		}

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

	// basic get route
	app.Get("/", func(c *fiber.Ctx) error {
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
	})

	// allow for heroku to set port
	port := ":" + os.Getenv("PORT")

	if port == "" {
		port = "5000"
	}
	app.Listen(port)
}
