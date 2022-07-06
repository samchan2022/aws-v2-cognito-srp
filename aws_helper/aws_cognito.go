package aws_helper

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
	// for sts session
	RoleArn string

	AWSUserAttr
}

type AWSUserAttr struct {
	Email         string
	GivenName     string
	FamilyName    string
	EmailVerified string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func NewCognitoClient(c AWSCognitoUser) (*CognitoClient, error) {
	// Store the Admin user
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
	if c.RoleArn != "" {
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), c.RoleArn)
	}

	cc := &CognitoClient{
		csrp:           csrp,
		AWSCognitoUser: c,
		svc:            cip.NewFromConfig(cfg),
	}
	return cc, err
}

func (cc *CognitoClient) AdminCreateUser(c AWSCognitoUser) (*cip.AdminCreateUserOutput, error) {
	userAttrs := []types.AttributeType{
		{
			Name:  aws.String("email"),
			Value: &c.AWSUserAttr.Email,
		},
		{
			Name:  aws.String("given_name"),
			Value: &c.AWSUserAttr.GivenName,
		},
		{
			Name:  aws.String("family_name"),
			Value: &c.AWSUserAttr.FamilyName,
		},
		{
			Name:  aws.String("email_verified"),
			Value: aws.String("true"),
		},
	}
	resp, err := cc.svc.AdminCreateUser(context.Background(), &cip.AdminCreateUserInput{
		UserPoolId:     aws.String(c.UserPoolId),
		Username:       aws.String(c.Username),
		UserAttributes: userAttrs,
		DesiredDeliveryMediums: []types.DeliveryMediumType{
			types.DeliveryMediumTypeEmail,
		},
	})

	if err != nil {
		panic(err)
	}

	return resp, err
}

func (cc *CognitoClient) AdminDeleteUser(username string) (*cip.AdminDeleteUserOutput, error) {
	resp, err := cc.svc.AdminDeleteUser(context.Background(), &cip.AdminDeleteUserInput{
		UserPoolId: aws.String(cc.AWSCognitoUser.UserPoolId),
		Username:   aws.String(username),
	})

	if err != nil {
		panic(err)
	}

	return resp, err
}

func (cc *CognitoClient) AdminAddUserToGroup(groupName, username string) (*cip.AdminAddUserToGroupOutput, error) {
	resp, err := cc.svc.AdminAddUserToGroup(context.Background(), &cip.AdminAddUserToGroupInput{
		GroupName:  aws.String(groupName),
		UserPoolId: aws.String(cc.AWSCognitoUser.UserPoolId),
		Username:   aws.String(username),
	})

	if err != nil {
		panic(err)
	}

	return resp, err
}

func (cc *CognitoClient) AdminGetUser(username string) (*cip.AdminGetUserOutput, error) {
	resp, err := cc.svc.AdminGetUser(context.Background(), &cip.AdminGetUserInput{
		UserPoolId: aws.String(cc.AWSCognitoUser.UserPoolId),
		Username:   aws.String(username),
	})

	if err != nil {
		panic(err)
	}

	return resp, err
}

func (cc *CognitoClient) AdminResetUserPassword(username string) (*cip.AdminResetUserPasswordOutput, error) {
	resp, err := cc.svc.AdminResetUserPassword(context.Background(), &cip.AdminResetUserPasswordInput{
		UserPoolId: aws.String(cc.AWSCognitoUser.UserPoolId),
		Username:   aws.String(username),
	})
	if err != nil {
		panic(err)
	}
	return resp, err
}

func (cc *CognitoClient) CreateGroup(groupName, desc, roleArn string) (bool, error) {
	_, err := cc.svc.CreateGroup(context.Background(), &cip.CreateGroupInput{
		GroupName:   aws.String(groupName),
		UserPoolId:  aws.String(cc.AWSCognitoUser.UserPoolId),
		Description: aws.String(desc),
		//Precedence:  nil,
		RoleArn: aws.String(roleArn),
	})
	if err != nil {
		panic(err)
		return false, err
	}
	return true, err
}

func (cc *CognitoClient) GetGroup(customer string) (*types.GroupType, error) {
	resp, err := cc.svc.GetGroup(context.Background(), &cip.GetGroupInput{
		GroupName:  aws.String(customer),
		UserPoolId: aws.String(cc.AWSCognitoUser.UserPoolId),
	})
	if err != nil {
		panic(err)
		return nil, err
	}
	return resp.Group, err
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

func (cc *CognitoClient) AdminUserGlobalSignOut(username string) (*cip.AdminUserGlobalSignOutOutput, error) {
	resp, err := cc.svc.AdminUserGlobalSignOut(context.Background(), &cip.AdminUserGlobalSignOutInput{
		UserPoolId: aws.String(cc.AWSCognitoUser.UserPoolId),
		Username:   aws.String(username),
	})

	if err != nil {
		panic(err)
	}

	return resp, err
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

func (cc *CognitoClient) ChangePassword(accessToken, previousPw, proposedPw string, args interface{}, callback func(interface{}) error) (bool, error) {
	resp, err := cc.svc.ChangePassword(context.Background(), &cip.ChangePasswordInput{
		AccessToken:      aws.String(accessToken),
		PreviousPassword: aws.String(previousPw),
		ProposedPassword: aws.String(proposedPw),
	})

	if err != nil {
		panic(err)
	}

	ok := resp.ResultMetadata.Has("HTTPStatusCode")
	if !ok {
		return false, err
	}

	if status := resp.ResultMetadata.Get("HTTPStatusCode"); status == 200 {
		// perform follow up action after password change, such as signout all users
		err := callback(args)
		if err != nil {
			panic(err)
			return false, err
		}
	}
	return true, nil
}
