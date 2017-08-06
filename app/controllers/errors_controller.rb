class ErrorsController < ApplicationController
  include AppsensorHelper

  def page_not_found
    user = get_current_user
    force_browsing_attempt(user)
    render file: "#{Rails.root}/public/404.html", status: 404
  end

  def robots
    user = try(:current_spree_user) ||  try(:current_admin)
    unless user
      force_browsing_attempt(user)
    end
    render file: "#{Rails.root}/public/robots_view.txt"
  end
end
