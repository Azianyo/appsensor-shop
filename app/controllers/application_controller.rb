class ApplicationController < ActionController::Base
  include AppsensorHelper
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :check_for_appsensor_events
  # rescue_from ActionController::InvalidAuthenticityToken, :with => :csrf_attempt

  def check_for_appsensor_events
    user = try(:current_user) || try(:current_admin) || request.remote_ip
    unexpected_http_method(user)
    unsupported_http_method(user)
    user_agent_change(user)
  end
end
