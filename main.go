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

	cc.GetCognitoTokens(user)
	var tokenResp *cognito.TokenResponse
	tokenResp = cc.GetCognitoTokens(user)
	//tokenResp = cognito.GetCognitoTokens(user)

	// print the tokens
	fmt.Printf("Access Token: %s\n", tokenResp.AccessToken)
	fmt.Printf("ID Token: %s\n", tokenResp.IdToken)
	fmt.Printf("Refresh Token: %s\n", tokenResp.RefreshToken)
}
