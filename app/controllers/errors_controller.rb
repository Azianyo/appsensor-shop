class ErrorsController < ApplicationController
  def page_not_found
    user = try(:current_user) || try(:current_admin) || request.remote_ip
    force_browsing_attempt(user)
    render file: "#{Rails.root}/public/404.html", status: 404
  end
end
