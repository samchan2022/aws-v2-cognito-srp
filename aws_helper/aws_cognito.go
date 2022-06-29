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
	svc *cip.Client
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

func NewCognitoClient(c AWSCognitoUser) (*CognitoClient, error) {
	csrp, err := cognitobase.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)
	if err != nil {
		panic(err)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(c.Region),
	)

	if err != nil {
		panic(err)
	}

	cc := &CognitoClient{
		csrp:           csrp,
		AWSCognitoUser: c,
		svc:            cip.NewFromConfig(cfg),
	}
	return cc, err
}

func (cc *CognitoClient) GetCognitoTokens(c AWSCognitoUser) (*TokenResponse, error) {
	var tokenResp = TokenResponse{}
	csrp, err := cognitobase.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)

	if err != nil {
		panic(err)
	}

	resp, err := cc.svc.InitiateAuth(context.Background(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})

	if err != nil {
		panic(err)
	}

	// respond to password verifier challenge
	if resp.ChallengeName == types.ChallengeNameTypePasswordVerifier {
		challengeResponses, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())

		resp, err := cc.svc.RespondToAuthChallenge(context.Background(), &cip.RespondToAuthChallengeInput{
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
	return &tokenResp, err
}

func (cc *CognitoClient) SetNewPassword(c AWSCognitoUser, newPassword, givenName, familyName string) (*TokenResponse, error) {
	var tokenResp = TokenResponse{}
	csrp, _ := cognitobase.NewCognitoSRP(c.Username, c.Password, c.UserPoolId, c.AppClientID, nil)

	// initiate auth
	resp, err := cc.svc.InitiateAuth(context.Background(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})

	if err != nil {
		panic(err)
	}

	// respond to password verifier challenge
	if resp.ChallengeName == types.ChallengeNameTypePasswordVerifier {
		challengeResponses, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())

		resp, err := cc.svc.RespondToAuthChallenge(context.Background(), &cip.RespondToAuthChallengeInput{
			ChallengeName:      types.ChallengeNameTypePasswordVerifier,
			ChallengeResponses: challengeResponses,
			ClientId:           aws.String(csrp.GetClientId()),
		})

		if err != nil {
			panic(err)
		}

		// respond to new pw challenge
		if resp.ChallengeName == types.ChallengeNameTypeNewPasswordRequired {
			challengeResponses := map[string]string{
				"USERNAME":                   csrp.GetUsername(),
				"NEW_PASSWORD":               newPassword,
				"userAttributes.given_name":  givenName,
				"userAttributes.family_name": familyName,
			}
			newPwResp, err := cc.svc.RespondToAuthChallenge(context.Background(), &cip.RespondToAuthChallengeInput{
				ChallengeName:      types.ChallengeNameTypeNewPasswordRequired,
				ChallengeResponses: challengeResponses,
				Session:            resp.Session,
				ClientId:           aws.String(csrp.GetClientId()),
			})
			if err != nil {
				panic(err)
			}
			tokenResp.AccessToken = *newPwResp.AuthenticationResult.AccessToken
			tokenResp.IdToken = *newPwResp.AuthenticationResult.IdToken
			tokenResp.RefreshToken = *newPwResp.AuthenticationResult.RefreshToken
			return &tokenResp, err
		}

		tokenResp.AccessToken = *resp.AuthenticationResult.AccessToken
		tokenResp.IdToken = *resp.AuthenticationResult.IdToken
		tokenResp.RefreshToken = *resp.AuthenticationResult.RefreshToken
	}
	return &tokenResp, err
}

func (cc *CognitoClient) RefreshToken(username, refreshToken string) (*TokenResponse, error) {
	var tokenResp = TokenResponse{}

	authParam := map[string]string{
		"USERNAME":      username,
		"REFRESH_TOKEN": refreshToken,
	}

	// initiate auth
	resp, err := cc.svc.InitiateAuth(context.Background(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeRefreshTokenAuth,
		ClientId:       aws.String(cc.AWSCognitoUser.AppClientID),
		AuthParameters: authParam,
	})

	if err != nil {
		panic(err)
	}

	tokenResp.AccessToken = *resp.AuthenticationResult.AccessToken
	tokenResp.IdToken = *resp.AuthenticationResult.IdToken
	return &tokenResp, err
}

func (cc *CognitoClient) ForgotPassword(username string) (*cip.ForgotPasswordOutput, error) {
	resp, err := cc.svc.ForgotPassword(context.Background(), &cip.ForgotPasswordInput{
		ClientId: aws.String(cc.AWSCognitoUser.AppClientID),
		Username: &username,
	},
	)
	if err != nil {
		panic(err)
	}
	return resp, err
}

func (cc *CognitoClient) ConfirmForgotPassword(username, confirmationCode, newPw string) (*cip.ConfirmForgotPasswordOutput, error) {
	resp, err := cc.svc.ConfirmForgotPassword(context.Background(), &cip.ConfirmForgotPasswordInput{
		ClientId:         aws.String(cc.AWSCognitoUser.AppClientID),
		Username:         &username,
		ConfirmationCode: &confirmationCode,
		Password:         &newPw,
	})
	if err != nil {
		panic(err)
	}
	return resp, err
}
