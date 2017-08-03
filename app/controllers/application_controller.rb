class ApplicationController < ActionController::Base
  include AppsensorHelper
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_filter :check_http_method
  # rescue_from ActionController::InvalidAuthenticityToken, :with => :csrf_attempt

  def check_http_method
    user = try(:current_user) || try(:current_admin) || request.remote_ip
    unexpected_http_method(user, request)
    unsupported_http_method(user, request)
  end
end
