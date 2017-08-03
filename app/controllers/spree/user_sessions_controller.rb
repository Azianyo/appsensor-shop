class Spree::UserSessionsController < Devise::SessionsController
  helper 'spree/base', 'spree/store'
  if Spree::Auth::Engine.dash_available?
    helper 'spree/analytics'
  end

  include Spree::Core::ControllerHelpers::Auth
  include Spree::Core::ControllerHelpers::Common
  include Spree::Core::ControllerHelpers::Order
  include Spree::Core::ControllerHelpers::Store
  include AppsensorHelper

  # This is included in ControllerHelpers::Order.  We just want to call
  # it after someone has successfully logged in.
  after_action :set_current_order, only: :create

  def create
    appsensor_scan(params)
    authenticate_spree_user!
    if spree_user_signed_in?
      create_auth_attempt(true)
      respond_to do |format|
        format.html do
          flash[:success] = Spree.t(:logged_in_succesfully)
          redirect_back_or_default(after_sign_in_path_for(spree_current_user))
        end
        format.js { render success_json }
      end
    else
      create_auth_attempt(false)
      respond_to do |format|
        format.html do
          flash.now[:error] = t('devise.failure.invalid')
          render :new
        end
        format.js do
          render json: { error: t('devise.failure.invalid') },
            status: :unprocessable_entity
        end
      end
    end
  end

  protected

  def required_params
    ["utf8", "authenticity_token", {"spree_user" => ["email", "password", "remember_me"]}, "commit", "controller", "action"]
  end

  def appsensor_scan(params)
    username = params["spree_user"]["email"]
    password = params["spree_user"]["password"]
    post_params_missing(username, params, required_params)
    additional_post_param(username, params, required_params)
    no_username(username)
    too_many_chars_in_username(username)
    common_username(username)
    no_password(username, password)
    too_many_chars_in_password(username, password)
    unexpected_char_in_username(username)
    unexpected_char_in_password(username, password)
  end

  def create_auth_attempt(successful)
    username = params["spree_user"]["email"]
    use_of_multiple_usernames(username)
    high_rate_of_login_attempts(username)
    multiple_failed_passwords(username, successful)
    high_number_of_logins
    AuthenticationAttempt.create(session_id: session.id,
                                 username: username,
                                 is_successful: successful,
                                 user_agent: request.headers["HTTP_USER_AGENT"],
                                 ip_address: request.remote_ip)

  end

  def translation_scope
    'devise.user_sessions'
  end

  private

  def accurate_title
    Spree.t(:login)
  end

  def redirect_back_or_default(default)
    redirect_to(session["spree_user_return_to"] || default)
    session["spree_user_return_to"] = nil
  end

  def success_json
    {
      json: {
        user: spree_current_user,
        ship_address: spree_current_user.ship_address,
        bill_address: spree_current_user.bill_address
      }.to_json
    }
  end
end
