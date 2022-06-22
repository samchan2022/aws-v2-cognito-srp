package aws_helper

import (
	"context"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp/v4"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type AWSCognitoUser struct {
	Username    string
	Password    string
	Region      string
	UserPoolId  string
	AppClientID string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func GetCognitoTokens(c AWSCognitoUser) *TokenResponse {
	var tokenResp = TokenResponse{}
	csrp, _ := cognitosrp.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)

	// configure cognito identity provider
	cfg, _ := config.LoadDefaultConfig(context.TODO(),
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
		tokenResp.IdToken = *resp.AuthenticationResult.IdToken
		tokenResp.RefreshToken = *resp.AuthenticationResult.RefreshToken
	}
	return &tokenResp
}
