package aws_helper

import (
	"context"
	"time"

	cognitobase "awshelper/cognito/aws_helper/base"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type CognitoClient struct {
	csrp *cognitobase.CognitoSRP
	AWSCognitoUser
}

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

func (cc CognitoClient) init(c AWSCognitoUser) {
	csrp, _ := cognitobase.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)

	cc.csrp = csrp
	cc.AWSCognitoUser = c

}

func (cc CognitoClient) GetClient() *cip.Client {
	// configure cognito identity provider
	cfg, _ := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(cc.AWSCognitoUser.Region),
	)
	return cip.NewFromConfig(cfg)
}

func (cc CognitoClient) GetCognitoTokens(c AWSCognitoUser) *TokenResponse {
	var tokenResp = TokenResponse{}
	csrp, _ := cognitobase.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)

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
