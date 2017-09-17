require 'net/http'
require 'time'
require 'csv'

module AppsensorEventHelper
  include AppsensorAdditionalHelper

  APPSENSOR_EVENT_MESSAGES = {
  "RE1" =>  "Unexpected HTTP Command",
  "RE2" =>  "Attempt to Invoke Unsupported HTTP Method",
  "RE5" =>  "Additional/Duplicated Data in Request",
  "RE6" =>  "Data Missing from Request",
  "RE7" =>  "Unexpected Quantity of Characters in Parameter",
  "RE8" =>  "Unexpected Type of Characters in Parameter",
  "AE1" =>  "Use of Multiple Usernames",
  "AE2" =>  "Multiple Failed Passwords",
  "AE3" =>  "High Rate of Login Attempts",
  "AE4" =>  "Unexpected Quantity of Characters in Username",
  "AE5" =>  "Unexpected Quantity of Characters in Password",
  "AE6" =>  "Unexpected Type of Character in Username",
  "AE7" =>  "Unexpected Type of Character in Password",
  "AE8" =>  "Providing Only the Username",
  "AE9" =>  "Providing Only the Password",
  "AE10" => "Additional POST Variable",
  "AE11" => "Missing POST Variable",
  "AE12" => "Utilization of Common Usernames",
  "AE13" => "Deviation from Normal GEO Location",
  "SE1" =>  "Modifying Existing Cookie",
  "SE2" =>  "Adding New Cookie",
  "SE3" =>  "Deleting Existing Cookie",
  "SE4" =>  "Substituting Another User's Valid Session ID or Cookie",
  "SE5" =>  "Source Location Changes During Session",
  "SE6" =>  "Change of User Agent Mid Session",
  "ACE3" => "Force Browsing Attempt",
  "IE1" =>  "Cross Site Scripting Attempt",
  "EE2" =>  "Unexpected Encoding Used",
  "CIE1" => "Blacklist Inspection for Common SQL Injection Values",
  "STE1" => "High Number of Logouts Across The Site",
  "STE2" => "High Number of Logins Across The Site",
  "CS1" =>  "Invalid CSRF Token"
  }

  APPSENSOR_EVENT_TYPES = {
    "AE" => "Authentication Exception",
    "IE" => "Input Validation",
    "RE" => "Request Exception",
    "SE" => "Session Exception",
    "AC" => "AccessControl Exception",
    "EE" => "Encoding Exception",
    "CI" => "Command Injection Exception",
    "ST" => "SystemTrend Exception",
    "CS" => "CSRF Exception"
  }

  def get_appsensor_reponses
    uri = URI.parse('http://localhost:8085/api/v1.0/responses')
    request = Net::HTTP::Get.new(uri, 'Content-Type' => 'application/json')
    request['X-API-Key'] = 'foobar'
    request['X-Appsensor-Client-Application-Name2'] = 'myclientapp'
    res = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end
    responses_json = JSON.parse(res.body)
    responses_json.map{ |json| extract_action_from_response(json) }
  end

  def extract_action_from_response(json)
    response = { action: json["action"],
                 user: json["user"]["username"],
                 timestamp: json["timestamp"]
               }
    response.merge!(interval: json["interval"]) if json["interval"]
    response
  end

  def logout_user(username)
    user = Spree::User.find_by(email: username)
    if user
      sign_out user
      puts "User #{username} has been signed out"
    end
  end


  def lockout_user(username, interval, timestamp)
    return unless interval
    time_period = interval["duration"].to_i.send(interval["unit"].to_sym)
    lockout_date = (timestamp.to_datetime.in_time_zone + time_period)
    user = Spree::User.find_by(email: username)
    return unless user
    if user.locked_until.nil?
      user.update_attributes(locked_until: lockout_date)
      sign_out user
    end
    return if timestamp.to_datetime.in_time_zone < user.locked_until
    return if DateTime.now.in_time_zone <= user.locked_until
    user.update_attributes(locked_until: lockout_date)
    sign_out user
  end

  def disable_auth_response(interval, timestamp)
    return unless interval
    time_period = interval["duration"].to_i.send(interval["unit"].to_sym)
    new_disable_auth_date = timestamp.to_datetime.in_time_zone + time_period
    disable_auth_date = SolidusDemo::Application.config.disable_auth_end_date
    if disable_auth_date.nil?
      disable_auth(new_disable_auth_date)
      return
    else
      return if timestamp.to_datetime.in_time_zone < disable_auth_date
      return if DateTime.now.in_time_zone <= disable_auth_date
      disable_auth(new_disable_auth_date)
    end
  end

  def disable_auth(new_disable_auth_date)
    Spree::User.all.each do |user|
      sign_out user
    end
    SolidusDemo::Application.config.disable_auth_end_date = new_disable_auth_date
  end

  def disable_app_for_user(username, interval, timestamp)
    return unless interval
    time_period = interval["duration"].to_i.send(interval["unit"].to_sym)
    new_disable_app_date = timestamp.to_datetime.in_time_zone + time_period
    disable_app_date = SolidusDemo::Application.config.disable_app_end_date
    if disable_app_date.nil?
      SolidusDemo::Application.config.disable_app_end_date = new_disable_app_date
      return
    else
      return if timestamp.to_datetime.in_time_zone < disable_app_date
      return if DateTime.now.in_time_zone <= disable_app_date
      SolidusDemo::Application.config.disable_app_end_date = new_disable_app_date
    end
  end

  def poll_for_response
    responses = get_appsensor_reponses
    responses.each do |response|
      case response[:action]
      when "logout"
        logout_user(response[:user])
      when "disableUser", "disableComponentForSpecificUser"
        lockout_user(response[:user], response[:interval], response[:timestamp])
      when "disableComponent"
        disable_auth_response(response[:interval], response[:timestamp])
      when "disable"
        disable_app_for_user(response[:user], response[:interval], response[:timestamp])
      else
      end
    end
  end

  def appsensor_event(username, users_ip, latitude=0, longitude=0, event_label)
    uri = URI.parse('http://localhost:8085/api/v1.0/events')
    appsensor_request = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
    appsensor_request['X-API-Key'] = 'foobar'
    appsensor_request['X-Appsensor-Client-Application-Name2'] = 'myclientapp'
    username = "null user" if username.blank?
    username = username.email if username.is_a? Spree::User
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

    appsensor_request.body = body.to_json
    puts get_appsensor_event_message(event_label)
    res = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(appsensor_request)
    end
    puts res
    write_to_report_file(event_label)
  end

  def write_to_report_file(event_label=nil)
    if File.exist?("report.csv")
      CSV.open("report.csv", "a+") do |csv|
        csv << create_csv_event_row(event_label)
      end
    else
      CSV.open("report.csv", "wb") do |csv|
        csv << ["Request URL", "Request Method", "Request Headers" ,"Request body", "Request Parameters", "Event label", "Event type"]
        csv << create_csv_event_row(event_label)
      end
    end
  end

  def create_csv_event_row(event_label=nil)
    raw_request = get_raw_request
    csv_line = [ "#{raw_request["Request URL"]}",
                "#{raw_request["Request Method"]}",
                "\"#{extract_headers(raw_request)}\"",
                "#{raw_request["Request Parameters"]}",
                "#{request.body.string}"]
    if event_label
      csv_line.concat(["#{event_label}", "#{get_appsensor_event_type(event_label)}"])
    else
      csv_line.concat([" ", " "])
    end
  end

  def get_raw_request
      req_headers = env.select {|k,v| k.start_with? 'HTTP_' || k.in?(ActionDispatch::Http::Headers::CGI_VARIABLES)}
          .collect {|pair| [pair[0].sub(/^HTTP_/, '').split('_').map(&:titleize).join('-'), pair[1]]}
          .sort
      req_params = request.request_parameters.map{|k, v| "#{k}: #{v}" }.join("\n")

      req_hash = {
        "REQUEST" => "",
        "Remote Address" => request.ip,
        "Request URL" => request.url,
        "Request Method" => request.request_method,
        "Request Parameters" => req_params,
        "REQUEST HEADERS" => ""
      }
      req_headers.to_a.each {|i| req_hash["\t" + i.first] = i.last }
      req_hash
  end

  def extract_headers(raw_request)
    raw_request.select{|k, v| k.starts_with?("\t")}.map{|k,v| "#{k}=#{v}"}.join.to_s.strip.gsub!("\t", "\n")
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

  def unexpected_http_method(username)
    unless ["POST", "GET", "DELETE"].include? request.request_method
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "RE1")
    end
  end

  def unsupported_http_method(username)
    unless ["POST", "GET", "DELETE", "HEAD", "PUT", "OPTIONS", "CONNECT"].include? request.request_method
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "RE2")
    end
  end

  def additional_data_in_request(username)
    if request.post?
      uri = URI.parse(request.original_url)
      url_params = CGI.parse(uri.query) if uri.query
      url_param_for_post = url_params.keys.any?{ |p| params.include?(p) } if url_params
    end
    http_headers = request.headers.env.keys
    duplicated_header = http_headers.count != http_headers.uniq.count
    # data_params = params.except("action", "controller")
    if duplicated_header || url_param_for_post #|| !data_params.empty? || !data_params.permitted?
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "RE5")
    end
  end

  def data_missing_from_request(username)
    if params.empty?
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "RE6")
    end
  end

  def unexpected_length_of_param(username)
    if params_too_long?(params)
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "RE7")
    end
  end

  def unexpected_type_of_chars_in_param(username)
    if params_contain_unexpected_chars?(params) || headers_contain_line_break?
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "RE8")
    end
  end

  def use_of_multiple_usernames(username)
    last_auth_attempt = AuthenticationAttempt.where(session_id: session.id).try(:last)
    if last_auth_attempt && last_auth_attempt.try(:username) != username
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE1")
    end
  end

  def multiple_failed_passwords(username, successful)
    if !successful && AuthenticationAttempt.where(session_id: session.id)
                                           .where(is_successful: false)
                                           .where("created_at >= ?", DateTime.now - 5.minutes)
                                           .count > 5
    appsensor_event(username,
                    request.remote_ip,
                    request.location.data["latitude"],
                    request.location.data["longitude"],
                    "AE2")
    end
  end

  def high_rate_of_login_attempts(username)
    if AuthenticationAttempt.where(session_id: session.id)
                            .where("created_at >= ?", DateTime.now - 2.seconds)
                            .count > 3
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE3")
    end
  end

  def too_many_chars_in_username(username)
    if username.nil? || username.length > 200
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE4")
    end
  end

  def too_many_chars_in_password(username, password)
    if password.nil? || password.length > 200
      appsensor_event(password,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE5")
    end
  end

  def unexpected_char_in_username(username)
    if contains_unexpected_chars?(username)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE6")
    end
  end

  def unexpected_char_in_password(username, password)
    if contains_unexpected_chars?(password)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE7")
    end
  end

  def no_password(username, password)
    if password.nil? || password.length == 0
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "AE8")
    end
  end

  def no_username(username)
    if username.nil? || username.length == 0
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE9")
    end
  end

  def additional_post_param(username, required_params)
    unless check_additional_params(params, required_params)
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "AE10")
    end
  end

  def post_params_missing(username, required_params)
    unless all_params?(params, required_params)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE11")
    end
  end

  def common_username(username)
    common_usernames = ["admin", "administrator", "root", "test", "admin@test.com"]
    if common_usernames.include?(username)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "AE12")
    end
  end


  def modifying_existing_cookie(username)
    response.cookies.keys.each do |cookie|
      if request.cookies.keys.include?(cookie)
        appsensor_event(username,
        request.remote_ip,
        request.location.data["latitude"],
        request.location.data["longitude"],
        "SE1")
      end
    end
  end

  def adding_new_cookie(username)
    # standard_cookies = ["__utma", "guest_token","JSESSIONID", "_solidus_demo_session"]
    response.cookies.keys.each do |cookie|
      unless request.cookies.keys.include?(cookie)
        appsensor_event(username,
                        request.remote_ip,
                        request.location.data["latitude"],
                        request.location.data["longitude"],
                        "SE2")
      end
    end
  end

  def deleting_existing_cookie(username)
    return if request.cookies.empty?
    standard_cookies = if try(:spree_current_user) || try(:current_admin)
                        ["guest_token", "_solidus_demo_session"]
                       else
                        ["guest_token"]
                       end
    unless (standard_cookies - request.cookies.keys).empty?
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "SE3")
    end
  end

  def substited_another_users_session(username)
    if response.cookies.keys.include?("_solidus_demo_session")
      appsensor_event(username,
      request.remote_ip,
      request.location.data["latitude"],
      request.location.data["longitude"],
      "SE4")
    end
  end

  def source_location_change(username)
    last_auth_attempt = AuthenticationAttempt.where(session_id: session.id).try(:last)
    if last_auth_attempt && session.id &&
       last_auth_attempt.try(:ip_address) != request.remote_ip
        appsensor_event(username,
                        request.remote_ip,
                        request.location.data["latitude"],
                        request.location.data["longitude"],
                        "SE5")
    end
  end

  def user_agent_change(username)
    last_auth_attempt = AuthenticationAttempt.where(session_id: session.id).try(:last)
    if last_auth_attempt && session.id &&
       last_auth_attempt.try(:user_agent) != request.headers["HTTP_USER_AGENT"]
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "SE6")
    end
  end

  def force_browsing_attempt(username)
    appsensor_event(username,
                    request.remote_ip,
                    request.location.data["latitude"],
                    request.location.data["longitude"],
                    "ACE3")
  end

  def xss_attempt(username)
    if xss_attempt?(params)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "IE1")
    end
  end

  def unexpected_encoding_used(username)
    unless valid_encoding_in_params?(params)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "EE2")
    end
  end

  def sql_injection_blacklist_inspection(username)
    if sql_injection_attempt?(params)
      appsensor_event(username,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "CIE1")
    end
  end

  def high_number_of_logouts
    appsensor_event(nil,
                    request.remote_ip,
                    request.location.data["latitude"],
                    request.location.data["longitude"],
                    "STE1")
  end

  def high_number_of_logins
    if AuthenticationAttempt.where("created_at >= ?", DateTime.now - 1.hour).count > 20
      appsensor_event(nil,
                      request.remote_ip,
                      request.location.data["latitude"],
                      request.location.data["longitude"],
                      "STE2")
    end
  end

  def invalid_csrf_token(username)
    appsensor_event(username,
                    request.remote_ip,
                    request.location.data["latitude"],
                    request.location.data["longitude"],
                    "CS1")
  end
end
