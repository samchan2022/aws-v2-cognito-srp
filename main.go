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

	givenName := os.Getenv("AWS_GIVEN_NAME")
	familyName := os.Getenv("AWS_FAMILY_NAME")
	email := os.Getenv("AWS_EMAIL")

	var userAttr = cognito.AWSUserAttr{
		Email:      email,
		GivenName:  givenName,
		FamilyName: familyName,
		//EmailVerified : aws.String("true"),
		EmailVerified: "true",
	}

	//refreshToken := os.Getenv("REFRESH_TOKEN")
	var user = cognito.AWSCognitoUser{
		AppClientID: appClientID,
		Password:    password,
		Region:      region,
		UserPoolId:  userPoolID,
		Username:    username,
		AWSUserAttr: userAttr,
	}

	cc, _ := cognito.NewCognitoClient(user)

	var tokenResp *cognito.TokenResponse
	// create user
	//---------------------------------------------------
	//newPw := os.Getenv("AWS_NEW_PW")
	//cc.AdminCreateUser(user)

	// Get user token
	//---------------------------------------------------
	tokenResp, _ = cc.GetCognitoTokens(user)

	// Set new pw
	//---------------------------------------------------

	//tokenResp, _ = cc.SetNewPassword(user, newPw, givenName, familyName)

	// ForgotPassword
	//---------------------------------------------------
	//resp, err := cc.ForgotPassword(username)
	//fmt.Println("resp", resp)

	// Confirm Forgot Password
	//---------------------------------------------------
	//confirmationCode := os.Getenv("AWS_CONFIRMATION_CODE")
	//newPw := os.Getenv("AWS_NEW_PW")
	//resp, err := cc.ConfirmForgotPassword(username, confirmationCode, newPw)
	//fmt.Println(resp)

	// print the tokens
	fmt.Printf("---------------------------------------------------\n")
	fmt.Printf("Access Token: %s\n\n", tokenResp.AccessToken)
	fmt.Printf("ID Token: %s\n\n", tokenResp.IdToken)
	fmt.Printf("Refresh Token: %s\n\n", tokenResp.RefreshToken)
}
