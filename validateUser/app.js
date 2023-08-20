const axios = require("axios");
const AWS = require("aws-sdk");

const NODE_ENV = "development";
const APP_ENTRY_POINT = "https://portal.isomarkets.com/api/redirect";
const CLIENT_ID = "3p0nrtgrkfdmvr481rrmdv8vrl";
const DOMAIN_URL = "https://appserver.auth.us-east-1.amazoncognito.com";
const COOKIE_EXPIRE_DAYS = 7;
const MAIN = "https://portal.isomarkets.com";

async function getObjectWrapper(bucket, key) {
  return new Promise((resolve, reject) => {
    var s3 = new AWS.S3();
    var params = {
      Bucket: bucket,
      Key: key,
    };
    s3.getObject(params, function (err, data) {
      if (err) {
        console.log(err, err.stack); // an error occurred
        reject(err);
      } else {
        const objectData = data.Body.toString("utf-8");
        resolve(objectData);
        console.log("success");
      }
    });
  });
}

function putObjectWrapper(bucket, key, data) {
  return new Promise((resolve, reject) => {
    var s3 = new AWS.S3();
    var params = {
      Bucket: bucket,
      Key: key,
      Body: data,
    };
    s3.putObject(params, function (err, data) {
      if (err) {
        console.log(err, err.stack); // an error occurred
        reject(err);
      } else {
        resolve(data);
        console.log("success");
      }
    });
  });
}

function getTokenA(refreshToken, code) {
  return new Promise((resolve, reject) => {
    console.log("new get token code = ", code);
    const parms = !refreshToken
      ? {
          grant_type: "authorization_code",
          client_id: `${CLIENT_ID}`,
          code,
          redirect_uri: `${APP_ENTRY_POINT}`,
        }
      : {
          grant_type: "refresh_token",
          client_id: `${CLIENT_ID}`,
          refresh_token: refreshToken,
          redirect_uri: `${APP_ENTRY_POINT}`,
        };

    axios
      .post(`${DOMAIN_URL}/oauth2/token`, null, {
        params: parms,
      })
      .then((response) => {
        console.log("got response");
        resolve(response);
      })
      .catch((error) => {
        console.log("got error");
        console.log("get token error=", error);
        reject(error);
      });
  });
}

async function getUserInfoA(accessToken) {
  return new Promise((resolve, reject) => {
    axios
      .get(`${DOMAIN_URL}/oauth2/userInfo`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })
      .then((response) => {
        resolve(response);
      })
      .catch((error) => {
        console.log("user info error response = ", error);
        reject(error);
      });
  });
}

exports.lambdaHandler = async (event, _context) => {
  //export const handler = async function(event, _context) {
  console.log("Received event:", JSON.stringify(event, null, 2));

  let userName;

  if (event.headers && event.headers.cookie) {
    const search = "userName=";
    const sampleUser = "89640ccd-6d81-498d-a7cf-c63c4a6f73bc";

    let start = event.headers.cookie.indexOf(search);

    console.log("start = ", start);
    console.log("cookie = ", event.headers.cookie);

    if (start !== -1) {
      start = start + search.length;
      userName = event.headers.cookie.substring(
        start,
        start + sampleUser.length
      );
    }
  }

  if (userName) {
    console.log("username = ", userName);

    let tokens;

    try {
      console.log("token validation/refresh 1");

      tokens = await getObjectWrapper(
        "user-tokens-fbf5be13-8cae-4eac-8c83-c80ceaf542c3",
        userName
      );

      console.log("token validation/refresh 2");

      tokens = JSON.parse(tokens);
      console.log("user validation ", tokens);

      console.log("token validation/refresh 3");

      try {
        tokens.accessToken;
        await getUserInfoA(tokens.access_token);
        console.log("token validation/refresh 4");

        generateAllow("me", event.methodArn);
        return Promise.resolve(generateAllow("me", event.methodArn));
      } catch (e) {
        console.log("token validation/refresh 5");

        //try to refresh
        try {
          console.log("token validation/refresh 6");

          const newAccessToken = await getTokenA(tokens.refresh_token);

          console.log("token validation/refresh 6a");

          console.log("newAccessToken =", newAccessToken);

          const newTokens = {
            ...tokens,
            access_token: newAccessToken.data.access_token,
          };

          console.log("token validation/refresh 7");

          await putObjectWrapper(
            "user-tokens-fbf5be13-8cae-4eac-8c83-c80ceaf542c3",
            userName,
            JSON.stringify(newTokens)
          );

          console.log("token validation/refresh 8");

          generateAllow("me", event.methodArn);

          return Promise.resolve(generateAllow("me", event.methodArn));
        } catch (e) {
          console.log("token validation/refresh 9");

          console.log("failed to refresh token error = " + e);

          return Promise.resolve(generateDeny("me", event.methodArn));
        }
      }
    } catch (e) {
      console.log(
        "Failed to read access token from s3 check permissions. " + e
      );

      return Promise.resolve(generateDeny("me", event.methodArn));
    }
  }

  // if ( cookie ) {
  //   callback(null, generateAllow('me', event.methodArn));
  // } else {
  //     callback(null, generateDeny('me', event.methodArn));
  // }
};

// Help function to generate an IAM policy
var generatePolicy = function (principalId, effect, resource) {
  // Required output:
  var authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = "2012-10-17"; // default version
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = "execute-api:Invoke"; // default action
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  // Optional output with custom properties of the String, Number or Boolean type.
  authResponse.context = {
    stringKey: "stringval",
    numberKey: 123,
    booleanKey: true,
  };
  return authResponse;
};

var generateAllow = function (principalId, resource) {
  return generatePolicy(principalId, "Allow", resource);
};

var generateDeny = function (principalId, resource) {
  return generatePolicy(principalId, "Deny", resource);
};
