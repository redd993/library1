class Entry < ActiveRecord::Base
    belongs_to :user
    has_many :comments
    validates :title, presence: true,
              length: {maximum: 50}
    validates :notes, presence: true
end
