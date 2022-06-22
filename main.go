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


type AWSCognitoUser struct {
    Username        string
    Password        string
    Region          string
    UserPoolId      string
    AppClientID     string
}

type TokenResponse struct {
    AccessToken  string `json:"access_token,omitempty"`
    IdToken      string `json:"id_token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
}

func getCognitoTokens( c AWSCognitoUser ) *TokenResponse {
    var tokenResp = TokenResponse{}
    csrp, _ := cognitosrp.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)

    // configure cognito identity provider
    cfg, _ := config.LoadDefaultConfig( context.TODO(),
        config.WithRegion(c.Region),
    )

    //config.WithCredentialsProvider(aws.AnonymousCredentials{}),
    svc := cip.NewFromConfig(cfg)

    // initiate auth
    //---------------------------------------------------
    resp, err := svc.InitiateAuth(context.Background(), &cip.InitiateAuthInput{
        AuthFlow:       types.AuthFlowTypeUserSrpAuth,
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

        tokenResp.AccessToken = *resp.AuthenticationResult.AccessToken
        tokenResp.IdToken =  *resp.AuthenticationResult.IdToken
        tokenResp.RefreshToken = *resp.AuthenticationResult.RefreshToken
    }
    return &tokenResp
}

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

    var user = AWSCognitoUser {
        AppClientID     : appClientID,
        Password        : password,
        Region          : region,
        UserPoolId      : userPoolID,
        Username        : username,
    }

    var tokenResp TokenResponse
    tokenResp = *getCognitoTokens(user)

    // print the tokens
    fmt.Printf("Access Token: %s\n", tokenResp.AccessToken)
    fmt.Printf("ID Token: %s\n", tokenResp.IdToken)
    fmt.Printf("Refresh Token: %s\n", tokenResp.RefreshToken)
}
