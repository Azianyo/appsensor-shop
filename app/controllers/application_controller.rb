class ApplicationController < ActionController::Base
  include ApplicationHelper
  include AppsensorEventHelper
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :check_for_appsensor_events

  rescue_from ActionController::UnknownController, with: :not_found
  rescue_from ActiveRecord::RecordNotFound,        with: :not_found
  rescue_from ActionController::MethodNotAllowed,  with: :weird_http_methods
  rescue_from ActionController::UnknownHttpMethod, with: :weird_http_methods

  def check_for_appsensor_events
    user = get_current_user
    unexpected_http_method(user)
    unsupported_http_method(user)
    # modifying_existing_cookie(user)
    adding_new_cookie(user)
    deleting_existing_cookie(user)
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

  def weird_http_methods
    user = get_current_user
    unexpected_http_method(user)
    unsupported_http_method(user)
  end

  def not_found
    user = get_current_user
    force_browsing_attempt(user)
  end
end
