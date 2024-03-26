import boto3, base64, re, json
from requests_toolbelt.multipart import decoder
import botocore.exceptions


# Initialize the Amazon Cognito client
cognito_client = boto3.client("cognito-idp", region_name=<your-region>)
cognito_client_id = <your-id>


# main function to handle all the requests
def lambda_handler(event, context):
    try:
        # getting action from Parameter
        action = event.get("queryStringParameters", {}).get("action")
        if action == "signup":
            return signup_user(event)
        elif action == "signin":
            return signin_user(event)
        elif action == "verify_user":
            return confirm_user(event)
        elif action == "new_confirmation_code":
            return request_new_confirmation_code(event)
        else:
            return {"statusCode": 400, "body": json.dumps("Invalid action")}

    except Exception as e:
        print(e)
        return {"statusCode": 500, "body": json.dumps("something went wrong")}


def signup_user(event):
    try:
        # Getting Content-Type to check it is multipart/form-data
        headers = event.get("headers", {})
        content_type = headers.get("Content-Type", "")
        # Getting body where form-data is located
        body = event.get("body")
        if not body or not content_type.startswith("multipart/form-data"):
            return {
                "statusCode": 400,
                "body": json.dumps(
                    "Requires Username and Password in multipart/form-data"
                ),
            }
        try:
            body_data = parsing_body(body, content_type)
        except Exception as e:
            print("Error:", e)
            return {"statusCode": 400, "body": json.dumps("Error parsing form data")}

        password = body_data.get("password")
        email = body_data.get("email")

        # if match found it returns email else None
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is None:
            return {"statusCode": 400, "body": json.dumps("email is not valid")}

        if email is None or password is None:
            return {
                "statusCode": 400,
                "body": json.dumps("email and password cannot be empty"),
            }

        try:
            # Call the sign-up API
            response = cognito_client.sign_up(
                ClientId=cognito_client_id, Username=email, Password=password
            )
            print("signup successfull :", response)
            return {
                "statusCode": 200,
                "body": json.dumps("User signed up successfully"),
            }
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            if error_code == "InvalidParameterException":
                # Handle invalid parameters (e.g., invalid email format)
                print("Invalid parameter:", error_message)
                return {"statusCode": 400, "body": json.dumps(error_message)}
            elif error_code == "InvalidPasswordException":
                # Handle invalid password (e.g., invalid email format)
                print("Invalid password:", error_message)
                return {
                    "statusCode": 400,
                    "body": json.dumps(
                        "password should be long and should have special"
                        "characters and numbers"
                    ),
                }
            elif error_code == "UsernameExistsException":
                # Handle existing username (email)
                print("Username (email) already exists:", error_message)
                return {
                    "statusCode": 400,
                    "body": json.dumps("Username (email) already exists"),
                }
            elif error_code == "LimitExceededException":
                # Handle limit exceeded (e.g., max number of users reached)
                print("Limit exceeded:")
                return {
                    "statusCode": 400,
                    "body": json.dumps("user limit exceeded"),
                }
            else:
                # Handle other errors
                print(error_code, error_message)
                return {
                    "statusCode": 400,
                    "body": json.dumps("something went wrong"),
                }
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps("Error signing up user")}


def signin_user(event):
    try:
        # Getting Content-Type to check it is multipart/form-data
        headers = event.get("headers", {})
        content_type = headers.get("Content-Type", "")
        # Getting body where form-data is located
        body = event.get("body")
        if not body or not content_type.startswith("multipart/form-data"):
            return {
                "statusCode": 400,
                "body": json.dumps(
                    "Requires Username and Password in multipart/form-data"
                ),
            }
        try:
            body_data = parsing_body(body, content_type)
        except Exception as e:
            print("Error:", e)
            return {"statusCode": 400, "body": json.dumps("Error parsing form data")}

        password = body_data.get("password")
        email = body_data.get("email")

        try:
            # Call the initiate-auth API to authenticate user
            response = cognito_client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": email,
                    "PASSWORD": password,
                },
                ClientId=cognito_client_id,
            )
            print(response)
            # Extract tokens from response
            access_token = response["AuthenticationResult"]["AccessToken"]
            id_token = response["AuthenticationResult"]["IdToken"]
            refresh_token = response["AuthenticationResult"]["RefreshToken"]

            # Return tokens
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "access_token": access_token,
                        "id_token": id_token,
                        "refresh_token": refresh_token,
                    }
                ),
            }
        except cognito_client.exceptions.NotAuthorizedException:
            print("Incorrect username or password.")
            return {
                "statusCode": 400,
                "body": json.dumps("Incorrect username or password."),
            }
        except cognito_client.exceptions.UserNotFoundException:
            print("User does not exist.")
            return {"statusCode": 400, "body": json.dumps("User does not exist.")}
        except cognito_client.exceptions.UserNotConfirmedException:
            print("User has not been confirmed.")
            return {
                "statusCode": 400,
                "body": json.dumps("User has not been confirmed."),
            }
        except cognito_client.exceptions.InvalidParameterException as e:
            print("Invalid parameter:", e)
            return {"statusCode": 400, "body": json.dumps("Invalid parameter")}
        except Exception as e:
            print("An unexpected error occurred:", e)
            return {
                "statusCode": 400,
                "body": json.dumps("An unexpected error occurred"),
            }

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps("something went wrong")}


def confirm_user(event):
    try:
        # Getting Content-Type to check it is multipart/form-data
        headers = event.get("headers", {})
        content_type = headers.get("Content-Type", "")
        # Getting body where form-data is located
        body = event.get("body")
        if not body or not content_type.startswith("multipart/form-data"):
            return {
                "statusCode": 400,
                "body": json.dumps(
                    "Requires email and confirmation_code in multipart/form-data"
                ),
            }
        try:
            body_data = parsing_body(body, content_type)
        except Exception as e:
            print("Error:", e)
            return {"statusCode": 400, "body": json.dumps("Error parsing form data")}
        email = body_data.get("email")
        confirmation_code = body_data.get("confirmation_code")
        if not confirmation_code or not email:
            return {
                "statusCode": 400,
                "body": json.dumps("confirmation code and email is required"),
            }
        try:
            # Call the confirm sign-up API
            response = cognito_client.confirm_sign_up(
                ClientId=cognito_client_id,
                Username=email,
                ConfirmationCode=confirmation_code,
            )
            print("User confirmed successfully:", response)
            return {
                "statusCode": 200,
                "body": json.dumps("User confirmed successfully"),
            }
        except cognito_client.exceptions.UserNotFoundException:
            print("User not found. Please make sure you have signed up.")
            return {
                "statusCode": 400,
                "body": json.dumps(
                    "User not found. Please make sure you have signed up."
                ),
            }
        except cognito_client.exceptions.CodeMismatchException:
            print("Invalid confirmation code. Please double-check the code.")
            return {
                "statusCode": 400,
                "body": json.dumps(
                    "Invalid confirmation code. Please double-check the code."
                ),
            }
        except cognito_client.exceptions.ExpiredCodeException:
            print("Confirmation code has expired. Please request a new code.")
            return {
                "statusCode": 400,
                "body": json.dumps(
                    "Confirmation code has expired. Please request a new code."
                ),
            }
        except cognito_client.exceptions.LimitExceededException:
            print("Request limit exceeded. Please try again later.")
            return {
                "statusCode": 400,
                "body": json.dumps("Request limit exceeded. Please try again later."),
            }
        except Exception as e:
            print("An unexpected error occurred:", e)
            return {
                "statusCode": 400,
                "body": json.dumps("An unexpected error occurred:"),
            }
    except Exception as e:
        print("Error confirming user:", e)
        return {"statusCode": 500, "body": json.dumps("Something went wrong")}


def request_new_confirmation_code(event):
    try:
        # Getting Content-Type to check it is multipart/form-data
        headers = event.get("headers", {})
        content_type = headers.get("Content-Type", "")

        # Getting body where form-data is located
        body = event.get("body")
        if not body or not content_type.startswith("multipart/form-data"):
            return {
                "statusCode": 400,
                "body": json.dumps("Requires email in multipart/form-data"),
            }
        try:
            body_data = parsing_body(body, content_type)
        except Exception as e:
            print("Error:", e)
            return {"statusCode": 400, "body": json.dumps("Error parsing form data")}
        email = body_data.get("email")
        # password = body_data.get('password')
    except Exception as e:
        print("error", e)
        return {"statusCode": 500, "body": json.dumps("something went wrong")}

    try:
        # Request new confirmation code
        response = cognito_client.resend_confirmation_code(
            ClientId=cognito_client_id, Username=email
        )
        print("New confirmation code requested successfully:", response)
        return {
            "statusCode": 200,
            "body": json.dumps("New confirmation code requested successfuly"),
        }
    except cognito_client.exceptions.UserNotFoundException:
        print("User not found. Please make sure you have signed up.")
        return {
            "statusCode": 400,
            "body": json.dumps("User not found. Please make sure you have signed up."),
        }
    except cognito_client.exceptions.NotAuthorizedException:
        print("User is not authorized to request a confirmation code.")
        return {
            "statusCode": 400,
            "body": json.dumps(
                "User is not authorized to request a confirmation code."
            ),
        }
    except cognito_client.exceptions.ResourceNotFoundException:
        print("ResourceNotFoundException.")
        return {
            "statusCode": 500,  # it is error from aws so set to 500
            "body": json.dumps("Resource not found"),
        }
    except Exception as e:
        print("An unexpected error occurred:", e)
        return {"statusCode": 500, "body": json.dumps("An unexpected error occurred")}


def parsing_body(body, content_type):
    # body is encoded from API Gateway, we decode and parse it.

    body_bytes = base64.b64decode(body)
    decoded_value = decoder.MultipartDecoder(body_bytes, content_type)

    body_data = {}
    for part in decoded_value.parts:
        # Get headers of the part
        headers = part.headers

        # Extract name attribute from Content-Disposition header
        content_disposition = headers[b"Content-Disposition"].decode("utf-8")
        name_start = content_disposition.find('name="') + len('name="')
        name_end = content_disposition.find('"', name_start)
        name = content_disposition[name_start:name_end]

        # Extract text content of the part
        value = part.text

        # Add key-value pair to body_data
        body_data[name] = value
    return body_data
