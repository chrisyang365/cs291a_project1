# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def is_json(body)
  JSON.parse(body) rescue false
end

def get_bearer_token(request)
  pattern = /^Bearer /
  header = request['headers']['Authorization']
  header.gsub(pattern, '') if header && header.match(pattern)
end

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  method = event['httpMethod']
  path = event['path']
  if path == '/'
    if method == 'GET'
      token = get_bearer_token(event)
      if token
        begin
          decoded_token = JWT.decode token, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }
          payload = decoded_token.first
          data = payload['data']
          response(body: data, status: 200)
        rescue JWT::ExpiredSignature
          response(body: nil, status: 401)
        rescue JWT::ImmatureSignature
          response(body: nil, status: 401)
        end
      else
        response(body: nil, status: 403)
      end
    else
      response(body: nil, status: 405)
    end
  elsif path == '/token'
    if method == 'POST'
      content_type = event['headers']['Content-Type']
      body = event['body'] ? event['body'] : ''
      if content_type != 'application/json'
        response(body: nil, status: 415)
      elsif !is_json(body)
        response(body: nil, status: 422)
      else
        payload = {
          data: body.to_json,
          exp: Time.now.to_i + 5,
          nbf: Time.now.to_i + 2
        }

        token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'

        response(body: "{'token': #{token}", status: 201)
      end
    else
      response(body: nil, status: 405)
    end
  else
    response(body: nil, status: 405)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
