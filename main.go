package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/twinj/uuid"
)

// https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/

var (
	router = gin.Default()
	client *redis.Client
	ctx    = context.Background()
)

func init() {
	// Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr:     dsn, // redis port
		Password: "",  // no password set
		DB:       0,   // use default DB
	})

	_, err := client.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}
}

// User is a struct for user
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenDetails includes access token and refresh token.
type TokenDetails struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccessUUID   string `json:"access_uuid"`
	RefreshUUID  string `json:"refresh_uuid"`
	AtExpires    int64  `json:"at_expires"`
	RtExpires    int64  `json:"rt_expires"`
}

// Todo is a struct for presentation what should be done in future.
type Todo struct {
	UserID uint64 `json:"user_id"`
	Title  string `json:"title"`
}

// AccessDetails includes access uuid and user id.
type AccessDetails struct {
	AccessUUID string `json:"access_uuid"`
	UserID     uint64 `json:"user_id"`
}

var user = User{
	ID:       1,
	Username: "username",
	Password: "password",
}

// CreateToken create a token for a user.
func CreateToken(userID int64) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUUID = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUUID = uuid.NewV4().String()

	var err error

	// Create access token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUUID
	atClaims["user_id"] = userID
	atClaims["exp"] = td.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	// Create refresh token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUUID
	rtClaims["user_id"] = userID
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}

	return td, nil
}

// CreateAuth save meta data of TokenDetails in redis.
func CreateAuth(userID int64, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) // converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(ctx, td.AccessUUID, strconv.Itoa(int(userID)), at.Sub(now)).Err() // context, key, value, expires time
	if errAccess != nil {
		return errAccess
	}

	errRefresh := client.Set(ctx, td.RefreshUUID, strconv.Itoa(int(userID)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}

	return nil
}

// Login login handler for user login.
// curl -i -X POST \
//   http://127.0.0.1:8080/login \
//   -H 'cache-control: no-cache' \
//   -H 'content-type: application/json' \
//   -d '{
//         "username":"username","password":"password"
// }'
func Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json provided")
		return
	}

	//Compare the user from the request with the one we defined.
	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnprocessableEntity, "please provide a valid login details")
		return
	}

	// Create a new token for the user.
	ts, err := CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	// save userID and token in the redis.
	saveErr := CreateAuth(user.ID, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}

	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}

	c.JSON(http.StatusOK, tokens)
}

// ExtractToken extracts the token from request headers.
func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// VerifyToken verifies the token method
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sigining method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// TokenVaild check the validity of this token.
func TokenVaild(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

// ExtractTokenMetadata return an `AccessDetails` struct containing the metadata(`access_uuid` and `user_id`)
func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUUID, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userID, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUUID: accessUUID,
			UserID:     userID,
		}, nil
	}
	return nil, err
}

// FetchAuth accepts the `AccessDetails` from the `ExtractTokenMetadata` function, then looks it up in redis.
func FetchAuth(authD *AccessDetails) (uint64, error) {
	userid, err := client.Get(ctx, authD.AccessUUID).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

// curl -i -X POST \
// -H 'Accept: application/json' \
// -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6IjBlNmRlNDkxLWViOGMtNGE5NC1hZjY3LWU3NDkxOTdmOTI3NiIsImF1dGhvcml6ZWQiOnRydWUsImV4cCI6MTYwOTQ5OTM5OCwidXNlcl9pZCI6MX0.5CCuL1RifAAMLEsZH6GUU6X5qnOp3OEx2lP3OyqP1AY" \
// -d '{
//         "title":"my first todo"
// }' \
// http://127.0.0.1:8080/todo

// CreateTodo creates a new Todo
func CreateTodo(c *gin.Context) {
	var td *Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}

	tokenAuth, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	// 通过AccessUUID查询用户的ID，如果AccessUUID不存在，则说明没有登录过。
	userID, err := FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userID

	c.JSON(http.StatusCreated, td)
}

func getTodos(c *gin.Context) {
	var todos = []string{"break", "continue", "fallthrough"}
	c.JSON(http.StatusOK, todos)
}

// DeleteAuth delete JWT info from Redis when user logs out.
// delete UserID through AccessUUID Key.
func DeleteAuth(givenUUID string) (int64, error) {
	deleted, err := client.Del(ctx, givenUUID).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// Logout log out handler
func Logout(c *gin.Context) {
	au, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	deleted, delErr := DeleteAuth(au.AccessUUID)
	if delErr != nil || deleted == 0 {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	c.JSON(http.StatusOK, "successfully logged out")
}

// TokenAuthMiddleware a middleware to secure some routes.
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := TokenVaild(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}

// Refresh refresh the token
// 为了安全起见，Refresh token 必须在授权后才能被调用
func Refresh(c *gin.Context) {
	mapToken := map[string]string{}
	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	// Get the refresh token from the request data.
	refreshToken := mapToken["refresh_token"]

	// verifies the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		// make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signinging method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	//if there is an error, the token must have expired
	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}
	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}

	// Since token is valid, get the UUID
	claims, ok := token.Claims.(jwt.MapClaims) // the token claims should confom to MapClaims
	if ok && token.Valid {
		refreshUUID, ok := claims["refresh_uuid"].(string) // convert the interface to string.
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userID, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, "error occurred")
			return
		}
		// Delete the previous Refresh token
		deleted, delErr := DeleteAuth(refreshUUID)
		if delErr != nil || deleted == 0 { // if any goes wrong
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}

		// Create new pairs of refresh and access tokens.
		ts, createErr := CreateToken(userID)
		if createErr != nil {
			c.JSON(http.StatusForbidden, createErr.Error())
			return
		}

		// Save the tokens metadata to redis.
		saveErr := CreateAuth(userID, ts)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}

		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	} else {
		c.JSON(http.StatusUnauthorized, "refresh expired")
	}
}

func main() {
	router.POST("/login", Login)
	router.POST("/todo", TokenAuthMiddleware(), CreateTodo)
	router.POST("/logout", TokenAuthMiddleware(), Logout)
	router.GET("/todos", TokenAuthMiddleware(), getTodos)
	router.POST("/token/refresh", Refresh)
	log.Fatal(router.Run(":8080"))
}
