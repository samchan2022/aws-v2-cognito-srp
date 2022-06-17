package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

    cognitosrp "github.com/alexrudd/cognito-srp/v4"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

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
    userPoolID := os.Getenv("AWS_COGNITO_USER_POOL_ID")
    username := os.Getenv("AWS_USERNAME")
    password := os.Getenv("AWS_PASSWORD")
    region := os.Getenv("AWS_REGION")
    //refresh := os.Getenv("REFRESH")
    //refreshToken := os.Getenv("REFRESH_TOKEN")

	// configure cognito srp
    //---------------------------------------------------
    // Currently for the aws cognito, it does not support the app secret
    // Remeber to get the user pool id only ( Not the identity pool, the user pool id should append with _, not colon )
    csrp, _ := cognitosrp.NewCognitoSRP(username, password, userPoolID, appClientID, nil)

	// configure cognito identity provider
	cfg, _ := config.LoadDefaultConfig( context.TODO(),
		config.WithRegion(region),
	)
		//config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	svc := cip.NewFromConfig(cfg)

	// initiate auth
    //---------------------------------------------------
	resp, err := svc.InitiateAuth(context.Background(), &cip.InitiateAuthInput{
        AuthFlow:       types.AuthFlowTypeUserSrpAuth,
        // For testing only user password
		//AuthFlow:       types.AuthFlowTypeAdminUserPasswordAuth,
        ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})

	if err != nil {
		panic(err)
	}

	// respond to password verifier challenge
    //---------------------------------------------------
	if resp.ChallengeName == types.ChallengeNameTypePasswordVerifier {
		challengeResponses, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())

		resp, err := svc.RespondToAuthChallenge(context.Background(), &cip.RespondToAuthChallengeInput{
			ChallengeName:      types.ChallengeNameTypePasswordVerifier,
			ChallengeResponses: challengeResponses,
            ClientId:           aws.String(csrp.GetClientId()),
		})
		if err != nil {
			panic(err)
		}

		// print the tokens
		fmt.Printf("Access Token: %s\n", *resp.AuthenticationResult.AccessToken)
		fmt.Printf("ID Token: %s\n", *resp.AuthenticationResult.IdToken)
		fmt.Printf("Refresh Token: %s\n", *resp.AuthenticationResult.RefreshToken)
	} else {
		// other challenges await...
	}
}
