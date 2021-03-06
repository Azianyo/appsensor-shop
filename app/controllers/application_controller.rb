class ApplicationController < ActionController::Base
  include ApplicationHelper
  include AppsensorEventHelper
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  # protect_from_forgery with: :exception
  before_filter :check_for_appsensor_events

  rescue_from ActionController::UnknownController, with: :not_found
  rescue_from ActiveRecord::RecordNotFound,        with: :not_found
  rescue_from ActionController::MethodNotAllowed,  with: :weird_http_methods
  rescue_from ActionController::UnknownHttpMethod, with: :weird_http_methods
  rescue_from ActionController::InvalidAuthenticityToken, with: :invalid_authenticity_token

  def check_for_appsensor_events
    write_to_report_file
    poll_for_response
    unless check_if_app_disabled
      user = get_current_user
      unexpected_http_method(user)
      unsupported_http_method(user)
      modifying_existing_cookie(user)
      adding_new_cookie(user)
      deleting_existing_cookie(user)
      substited_another_users_session(user)
      source_location_change(user)
      user_agent_change(user)
      data_missing_from_request(user)
      additional_data_in_request(user)
      unexpected_length_of_param(user)
      unexpected_type_of_chars_in_param(user)
      xss_attempt(user)
      unexpected_encoding_used(user)
      sql_injection_blacklist_inspection(user)
    end
  end

  def check_if_app_disabled
    disable_app_date = SolidusDemo::Application.config.disable_app_end_date
    if disable_app_date && DateTime.now.in_time_zone <= disable_app_date
      render text: "Permission denied", status: :unauthorized
      return true
    end
    false
  end

  def weird_http_methods
    user = get_current_user
    unexpected_http_method(user)
    unsupported_http_method(user)
  end

  def invalid_authenticity_token
    user = get_current_user
    invalid_csrf_token(user)
  end

  def not_found
    user = get_current_user
    force_browsing_attempt(user)
  end
end
