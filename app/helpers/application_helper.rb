module ApplicationHelper
  def get_current_user
    try(:current_spree_user) || try(:current_admin) || request.remote_ip
  end
end
