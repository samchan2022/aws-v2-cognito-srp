package main

import (
	cognito "awshelper/cognito/aws_helper"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// load the os environments
	//---------------------------------------------------

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	appClientID := os.Getenv("AWS_APP_CLIENT_ID")
	password := os.Getenv("AWS_PASSWORD")
	region := os.Getenv("AWS_REGION")
	userPoolID := os.Getenv("AWS_COGNITO_USER_POOL_ID")
	username := os.Getenv("AWS_USERNAME")

	newPw := os.Getenv("AWS_NEW_PW")
	givenName := os.Getenv("AWS_GIVEN_NAME")
	familyName := os.Getenv("AWS_FAMILY_NAME")

	//refreshToken := os.Getenv("REFRESH_TOKEN")
	var user = cognito.AWSCognitoUser{
		AppClientID: appClientID,
		Password:    password,
		Region:      region,
		UserPoolId:  userPoolID,
		Username:    username,
	}

	cc := cognito.CognitoClient{
		AWSCognitoUser: user,
	}

	//cognitoClient := cc.GetClient()
	var tokenResp *cognito.TokenResponse

    // RefreshToken
	//tokenResp = cc.RefreshToken(cognitoClient, username, refreshToken)

    // Get token
	//tokenResp = cc.GetCognitoTokens(user)

    // Set new pw
	tokenResp = cc.SetNewPassword(user, newPw, givenName, familyName)

	// print the tokens
	fmt.Printf("Access Token: %s\n", tokenResp.AccessToken)
	fmt.Printf("ID Token: %s\n", tokenResp.IdToken)
	fmt.Printf("Refresh Token: %s\n", tokenResp.RefreshToken)
}
