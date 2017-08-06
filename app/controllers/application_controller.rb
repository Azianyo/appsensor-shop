class ApplicationController < ActionController::Base
  include ApplicationHelper
  include AppsensorHelper
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
    user_agent_change(user)
    source_location_change(user)
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
