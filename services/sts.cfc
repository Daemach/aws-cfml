/**
* AWS Security Token Service (STS) - Temporary credential management and cross-account access
* https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html
*
* ================================================================================
* CROSS-ACCOUNT ACCESS SETUP GUIDE
* ================================================================================
*
* This service enables Account A (your application) to access resources in Account B
* by assuming an IAM role. Here's how to set it up:
*
* ACCOUNT B (Target Account - where resources live):
* -------------------------------------------------
* 1. Create an IAM Role with a trust policy allowing Account A to assume it:
*
*    Trust Policy (who can assume this role):
*    {
*        "Version": "2012-10-17",
*        "Statement": [{
*            "Effect": "Allow",
*            "Principal": {
*                "AWS": "arn:aws:iam::ACCOUNT_A_ID:root"
*            },
*            "Action": "sts:AssumeRole",
*            "Condition": {
*                "StringEquals": {
*                    "sts:ExternalId": "your-secret-external-id"  // Optional but recommended
*                }
*            }
*        }]
*    }
*
* 2. Attach permission policies to the role for what it can access (e.g., DynamoDB, S3)
*
* 3. Note the Role ARN: arn:aws:iam::ACCOUNT_B_ID:role/YourRoleName
*
* ACCOUNT A (Source Account - where your app runs):
* -------------------------------------------------
* 1. The IAM user/role running your CFML app needs permission to assume the role:
*
*    {
*        "Version": "2012-10-17",
*        "Statement": [{
*            "Effect": "Allow",
*            "Action": "sts:AssumeRole",
*            "Resource": "arn:aws:iam::ACCOUNT_B_ID:role/YourRoleName"
*        }]
*    }
*
* AWS Console Links:
* - Create IAM Role: https://console.aws.amazon.com/iam/home#/roles
* - IAM Policy Simulator: https://policysim.aws.amazon.com/
* - STS Documentation: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
*
* ================================================================================
* CFML USAGE EXAMPLES
* ================================================================================
*
* Basic cross-account access:
*
*    // Assume role in target account
*    var stsResponse = aws.sts.assumeRole(
*        RoleArn         = "arn:aws:iam::123456789012:role/CrossAccountRole",
*        RoleSessionName = "MyAppSession"
*    );
*
*    if ( stsResponse.statusCode != 200 ) {
*        throw( "Failed to assume role: " & stsResponse.rawData );
*    }
*
*    // Use temporary credentials with any other AWS service
*    var dynamoResult = aws.dynamodb.scan(
*        TableName      = "my-table-in-account-b",
*        awsCredentials = stsResponse.credentials
*    );
*
*    var s3Result = aws.s3.getObject(
*        bucket         = "my-bucket-in-account-b",
*        objectKey      = "myfile.txt",
*        awsCredentials = stsResponse.credentials
*    );
*
* With ExternalId (recommended for third-party access):
*
*    var stsResponse = aws.sts.assumeRole(
*        RoleArn         = "arn:aws:iam::123456789012:role/CrossAccountRole",
*        RoleSessionName = "MyAppSession",
*        ExternalId      = "your-secret-external-id"
*    );
*
* Caching credentials (they expire after DurationSeconds, default 1 hour):
*
*    // Store in application or variables scope
*    if ( structIsEmpty( application.cachedCreds ) ||
*         parseDateTime( application.cachedCreds.expiration ) <= dateAdd( "n", 5, now() ) ) {
*        var response = aws.sts.assumeRole( ... );
*        application.cachedCreds = response.credentials;
*    }
*    // Use application.cachedCreds.awsKey, .awsSecretKey, .token
*
* Returned credentials struct:
*    {
*        "awsKey"       : "ASIA...",           // Temporary access key
*        "awsSecretKey" : "...",               // Temporary secret key
*        "token"        : "...",               // Session token (required for temp creds)
*        "expiration"   : "2024-01-15T12:00:00Z"  // When credentials expire
*    }
*
* ================================================================================
* SECURITY NOTES
* ================================================================================
* - NEVER derive RoleArn from untrusted user input - always hardcode or whitelist
* - Use ExternalId for roles assumed by third parties (prevents confused deputy)
* - Credentials are temporary and auto-expire; cache them but handle refresh
* - The minimum DurationSeconds is 900 (15 min), maximum depends on role settings
* - All authorization is enforced by AWS IAM - this library is a passthrough
*/
component {

    variables.service = 'sts';

    public any function init(
        required any api,
        required struct settings
    ) {
        variables.api = arguments.api;
        variables.apiVersion = arguments.settings.apiVersion;
        return this;
    }

    /**
    * Returns a set of temporary security credentials that you can use to access AWS resources that you might not normally have access to.
    * https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
    * @RoleArn The Amazon Resource Name (ARN) of the role to assume.
    * @RoleSessionName An identifier for the assumed role session.
    * @DurationSeconds The duration, in seconds, of the role session. Default is 3600 (1 hour).
    * @ExternalId A unique identifier that might be required when you assume a role in another account.
    * @Policy An IAM policy in JSON format that you want to use as an inline session policy.
    * @PolicyArns The Amazon Resource Names (ARNs) of the IAM managed policies to use as managed session policies.
    * @SerialNumber The identification number of the MFA device.
    * @TokenCode The value provided by the MFA device.
    */
    public any function assumeRole(
        required string RoleArn,
        required string RoleSessionName,
        numeric DurationSeconds = 3600,
        string ExternalId = '',
        string Policy = '',
        array PolicyArns = [ ],
        string SerialNumber = '',
        string TokenCode = ''
    ) {
        var requestSettings = api.resolveRequestSettings( argumentCollection = arguments );
        var queryParams = {
            'Action' : 'AssumeRole',
            'Version' : variables.apiVersion,
            'RoleArn' : arguments.RoleArn,
            'RoleSessionName' : arguments.RoleSessionName,
            'DurationSeconds' : arguments.DurationSeconds
        };

        if ( len( arguments.ExternalId ) ) {
            queryParams[ 'ExternalId' ] = arguments.ExternalId;
        }
        if ( len( arguments.Policy ) ) {
            queryParams[ 'Policy' ] = arguments.Policy;
        }
        if ( arguments.PolicyArns.len() ) {
            for ( var i = 1; i <= arguments.PolicyArns.len(); i++ ) {
                queryParams[ 'PolicyArns.member.#i#.arn' ] = arguments.PolicyArns[ i ];
            }
        }
        if ( len( arguments.SerialNumber ) ) {
            queryParams[ 'SerialNumber' ] = arguments.SerialNumber;
        }
        if ( len( arguments.TokenCode ) ) {
            queryParams[ 'TokenCode' ] = arguments.TokenCode;
        }

        var apiResponse = apiCall( requestSettings, queryParams );

        // Parse credentials from response if successful
        if ( apiResponse.statusCode == 200 && isXML( apiResponse.rawData ) ) {
            var parsed = variables.api.getUtils().parseXmlDocument( apiResponse.rawData );
            if (
                structKeyExists( parsed, 'AssumeRoleResult' ) &&
                structKeyExists( parsed.AssumeRoleResult, 'Credentials' )
            ) {
                apiResponse[ 'credentials' ] = {
                    'awsKey' : parsed.AssumeRoleResult.Credentials.AccessKeyId,
                    'awsSecretKey' : parsed.AssumeRoleResult.Credentials.SecretAccessKey,
                    'token' : parsed.AssumeRoleResult.Credentials.SessionToken,
                    'expiration' : parsed.AssumeRoleResult.Credentials.Expiration
                };
            }
        }

        return apiResponse;
    }

    /**
    * Returns details about the IAM user or role whose credentials are used to call the operation.
    * https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
    */
    public any function getCallerIdentity() {
        var requestSettings = api.resolveRequestSettings( argumentCollection = arguments );
        var queryParams = {
            'Action' : 'GetCallerIdentity',
            'Version' : variables.apiVersion
        };
        return apiCall( requestSettings, queryParams );
    }

    /**
    * Returns a set of temporary security credentials for a federated user.
    * https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
    * @Name The name of the federated user.
    * @DurationSeconds The duration, in seconds, of the session. Default is 43200 (12 hours).
    * @Policy An IAM policy in JSON format that you want to use as an inline session policy.
    * @PolicyArns The Amazon Resource Names (ARNs) of the IAM managed policies to use as managed session policies.
    */
    public any function getFederationToken(
        required string Name,
        numeric DurationSeconds = 43200,
        string Policy = '',
        array PolicyArns = [ ]
    ) {
        var requestSettings = api.resolveRequestSettings( argumentCollection = arguments );
        var queryParams = {
            'Action' : 'GetFederationToken',
            'Version' : variables.apiVersion,
            'Name' : arguments.Name,
            'DurationSeconds' : arguments.DurationSeconds
        };

        if ( len( arguments.Policy ) ) {
            queryParams[ 'Policy' ] = arguments.Policy;
        }
        if ( arguments.PolicyArns.len() ) {
            for ( var i = 1; i <= arguments.PolicyArns.len(); i++ ) {
                queryParams[ 'PolicyArns.member.#i#.arn' ] = arguments.PolicyArns[ i ];
            }
        }

        var apiResponse = apiCall( requestSettings, queryParams );

        // Parse credentials from response if successful
        if ( apiResponse.statusCode == 200 && isXML( apiResponse.rawData ) ) {
            var parsed = variables.api.getUtils().parseXmlDocument( apiResponse.rawData );
            if (
                structKeyExists( parsed, 'GetFederationTokenResult' ) &&
                structKeyExists( parsed.GetFederationTokenResult, 'Credentials' )
            ) {
                apiResponse[ 'credentials' ] = {
                    'awsKey' : parsed.GetFederationTokenResult.Credentials.AccessKeyId,
                    'awsSecretKey' : parsed.GetFederationTokenResult.Credentials.SecretAccessKey,
                    'token' : parsed.GetFederationTokenResult.Credentials.SessionToken,
                    'expiration' : parsed.GetFederationTokenResult.Credentials.Expiration
                };
            }
        }

        return apiResponse;
    }

    /**
    * Returns a set of temporary credentials for an AWS account or IAM user without requiring MFA.
    * https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html
    * @DurationSeconds The duration, in seconds, of the session. Default is 43200 (12 hours).
    * @SerialNumber The identification number of the MFA device.
    * @TokenCode The value provided by the MFA device.
    */
    public any function getSessionToken(
        numeric DurationSeconds = 43200,
        string SerialNumber = '',
        string TokenCode = ''
    ) {
        var requestSettings = api.resolveRequestSettings( argumentCollection = arguments );
        var queryParams = {
            'Action' : 'GetSessionToken',
            'Version' : variables.apiVersion,
            'DurationSeconds' : arguments.DurationSeconds
        };

        if ( len( arguments.SerialNumber ) ) {
            queryParams[ 'SerialNumber' ] = arguments.SerialNumber;
        }
        if ( len( arguments.TokenCode ) ) {
            queryParams[ 'TokenCode' ] = arguments.TokenCode;
        }

        var apiResponse = apiCall( requestSettings, queryParams );

        // Parse credentials from response if successful
        if ( apiResponse.statusCode == 200 && isXML( apiResponse.rawData ) ) {
            var parsed = variables.api.getUtils().parseXmlDocument( apiResponse.rawData );
            if (
                structKeyExists( parsed, 'GetSessionTokenResult' ) &&
                structKeyExists( parsed.GetSessionTokenResult, 'Credentials' )
            ) {
                apiResponse[ 'credentials' ] = {
                    'awsKey' : parsed.GetSessionTokenResult.Credentials.AccessKeyId,
                    'awsSecretKey' : parsed.GetSessionTokenResult.Credentials.SecretAccessKey,
                    'token' : parsed.GetSessionTokenResult.Credentials.SessionToken,
                    'expiration' : parsed.GetSessionTokenResult.Credentials.Expiration
                };
            }
        }

        return apiResponse;
    }

    // private methods

    private any function apiCall(
        required struct requestSettings,
        required struct queryParams
    ) {
        var host = variables.service & '.' & requestSettings.region & '.amazonaws.com';

        var apiResponse = api.call(
            variables.service,
            host,
            requestSettings.region,
            'POST',
            '/',
            queryParams,
            { 'Content-Type' : 'application/x-www-form-urlencoded' },
            '',
            requestSettings.awsCredentials
        );

        if ( apiResponse.statusCode != 200 && isXML( apiResponse.rawData ) ) {
            apiResponse[ 'error' ] = variables.api.getUtils().parseXmlDocument( apiResponse.rawData );
        }

        return apiResponse;
    }

}
