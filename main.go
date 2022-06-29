package main

import (
	cognito "awshelper/cognito/aws_helper"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func main() {
	// load the os environments
	//---------------------------------------------------
	err := godotenv.Load()
	if err != nil {
		log.Error().Msgf("Error loading .env file")
	}

	appClientID := os.Getenv("AWS_APP_CLIENT_ID")
	password := os.Getenv("AWS_PASSWORD")
	region := os.Getenv("AWS_REGION")
	userPoolID := os.Getenv("AWS_COGNITO_USER_POOL_ID")
	username := os.Getenv("AWS_USERNAME")

	//refreshToken := os.Getenv("REFRESH_TOKEN")
	var user = cognito.AWSCognitoUser{
		AppClientID: appClientID,
		Password:    password,
		Region:      region,
		UserPoolId:  userPoolID,
		Username:    username,
	}

	cc, _ := cognito.NewCognitoClient(user)

	var tokenResp *cognito.TokenResponse

	// Set new pw
	//---------------------------------------------------
	//newPw := os.Getenv("AWS_NEW_PW")
	//givenName := os.Getenv("AWS_GIVEN_NAME")
	//familyName := os.Getenv("AWS_FAMILY_NAME")
	//tokenResp, _ = cc.SetNewPassword(user, newPw, givenName, familyName)

	// ForgotPassword
	//---------------------------------------------------
	//_, err = cc.ForgotPassword(username)

	// Confirm Forgot Password
	//---------------------------------------------------
	//confirmationCode := os.Getenv("AWS_CONFIRMATION_CODE")
	//newPw := os.Getenv("AWS_NEW_PW")
	//_, err = cc.ConfirmForgotPassword(username, confirmationCode, newPw)

	// print the tokens
	fmt.Printf("Access Token: %s\n", tokenResp.AccessToken)
	fmt.Printf("ID Token: %s\n", tokenResp.IdToken)
	fmt.Printf("Refresh Token: %s\n", tokenResp.RefreshToken)
	fmt.Println(tokenResp)
}
