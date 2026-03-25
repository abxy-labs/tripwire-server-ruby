module Tripwire
  module Server
    ListResult = Struct.new(:items, :limit, :has_more, :next_cursor, keyword_init: true)
  end
end
