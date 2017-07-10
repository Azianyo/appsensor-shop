require 'net/http'
require 'time'

module AppsensorHelper
  def appsensor_event
    uri = URI.parse('http://localhost:8085/api/v1.0/events')
    request = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
    request['X-API-Key'] = 'foobar'
    request['X-Appsensor-Client-Application-Name2'] = 'myclientapp'
    body = { user:
              { username: "ian",
                ipAddress:
                { address: "10.10.10.1",
                  geoLocation: { latitude: 37.596758, longitude: -121.647992 }
                }
              },
              detectionPoint: { category: "Input Validation", label: "IE1", responses: [] },
              timestamp: Time.now.utc.iso8601, #"2017-07-01T15:02:45.392Z"
              detectionSystem: { detectionSystemId: "myclientapp" },
              metadata: []
            }

    request.body = body.to_json
    res = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end
  end
end
