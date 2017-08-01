require 'net/http'
require 'time'

module AppsensorHelper
  APPSENSOR_EVENT_MESSAGES = {
  "AE1" => "Use of Multiple Usernames",
  "AE2" => "Multiple Failed Passwords",
  "AE3" => "High Rate of Login Attempts",
  "AE4" => "Unexpected Quantity of Characters in Username",
  "AE5" => "Unexpected Quantity of Characters in Password",
  "AE6" => "Unexpected Type of Character in Username",
  "AE7" => "Unexpected Type of Character in Password",
  "AE8" => "Providing Only the Username",
  "AE9" => "Providing Only the Password",
  "AE10" => "Additional POST Variable",
  "AE11" => "Missing POST Variable",
  "AE12" => "Utilization of Common Usernames",
  "AE13" => "Deviation from Normal GEO Location"
  }

  APPSENSOR_EVENT_TYPES = {
    "AE" => "Authentication Exception",
    "IE" => "Input Validation"
  }
  def appsensor_event(username, users_ip, latitude=0, longitude=0, event_label)
    uri = URI.parse('http://localhost:8085/api/v1.0/events')
    request = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
    request['X-API-Key'] = 'foobar'
    request['X-Appsensor-Client-Application-Name2'] = 'myclientapp'
    username = "null user" if username.blank?
    body = { user:
              { username: username,
                ipAddress:
                { address: users_ip,
                  geoLocation: { latitude: latitude.to_f, longitude: longitude.to_f }
                }
              },
              detectionPoint: { category: get_appsensor_event_type(event_label), label: event_label, responses: [] },
              timestamp: Time.now.utc.iso8601(3), #"2017-07-01T15:02:45.392Z" \"timestamp\":\"2017-07-16T16:38:44Z\"
              detectionSystem: { detectionSystemId: "myclientapp" },
              metadata: []
            }

    request.body = body.to_json
    puts get_appsensor_event_message(event_label)
    res = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end
    puts res
  end

  def get_appsensor_event_type(event_label)
    event_type = APPSENSOR_EVENT_TYPES[event_label[0..1]]
    return "Unknown Event" unless event_type
    event_type
  end

  def get_appsensor_event_message(event_label)
    event_msg = APPSENSOR_EVENT_MESSAGES[event_label]
    return "Unknown Event" unless event_msg
    event_msg
  end

  def too_many_chars_in_username(username, request)
    if username.length > 200
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE4")
    end
  end

  def too_many_chars_in_password(username, request, password)
    if password.length > 200
      appsensor_event(password,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE5")
    end
  end

  def no_username(username, request)
    if username.length == 0
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE9")
    end
  end

  def no_password(username, request, password)
    if password.length == 0
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE8")
    end
  end

  def post_params_missing(username, request, params, required_params)
    unless all_params?(params, required_params)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE11")
    end
  end

  def all_params?(params, required_params)
    required_params.all? do |name|
      if name.is_a?(Hash)
        unless params.key?(name.keys[0])
          puts "parameter missing #{name.keys[0]}"
          return false
        end
        name.values[0].all? do |value|
          puts "parameter missing #{name.keys[0]}" unless params[name.keys[0]].key?(value)
          params[name.keys[0]].key?(value)
        end
      else
        params.key?(name)
      end
    end
  end

  def common_username(username, request)
    common_usernames = ["admin", "administrator", "root", "test", "admin@test.com"]
    if common_usernames.include?(username)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE12")
    end
  end

end
