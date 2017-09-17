class AddDisabledUntilToSpreeUsers < ActiveRecord::Migration
  def change
    add_column :spree_users, :disabled_until, :datetime
  end
end
