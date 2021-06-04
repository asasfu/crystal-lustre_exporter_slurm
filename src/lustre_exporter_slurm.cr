require "http/client"
require "kemal"
require "ldap"
require "lru-cache"
require "ini"
require "db"
require "mysql"

class Lustre_exporter_slurm
  property ldap_host
  property ldap_port
  property search_base
  @db_database : DB::Database
  def initialize(
      @ldap_host   : String, 
      @ldap_port   : Int32,
      @ldap_ssl    : Bool,
      @ldap_tls    : Bool,
      @search_base : String,
      @db_host     : String,
      @db_port     : Int32 | Nil,
      @db_user     : String,
      @db_pass     : String,
      @db_name     : String,
      @db_table    : String
    )
    # Currently we always do LDAPS, we never prepared a method for START_TLS so we ignore @ldap_tls
    ldap_socket = TCPSocket.new(@ldap_host, @ldap_port)
    if @ldap_ssl
      tls = OpenSSL::SSL::Context::Client.new
      tls.verify_mode = OpenSSL::SSL::VerifyMode::FAIL_IF_NO_PEER_CERT
      ldap_socket = OpenSSL::SSL::Socket::Client.new(ldap_socket, context: tls, sync_close: true, hostname: @ldap_host)
    end
    @ldap_client = LDAP::Client.new(ldap_socket)
    @jobs_cache = LRUCache(UInt32, NamedTuple(user: String,account: String) | Nil).new(max_size: 300_000)
    @uid_cache = LRUCache(String, String).new(max_size: 10_000)
    @uid_cache_misses = 0
    @jobs_cache_misses = 0
    @jobs_mutex = Mutex.new
    @uid_mutex = Mutex.new
    # Prepare the DB
    db_uri = URI.new(
        scheme: "mysql",
        host:   @db_host,
        port:   @db_port,
        path:   "/#{@db_name}",
        user:   @db_user,
        password: @db_pass
      )
    @db_database = DB.open(db_uri)
  end
  def close
    @ldap_client.close
    @db_database.close
  end
  def get_stats
    {
      "UID_Cache_size" => "#{@uid_cache.size}/#{@uid_cache.max_size}",
      "Jobs_Cache_size" => "#{@jobs_cache.size}/#{@jobs_cache.max_size}",
      "UID_Cache_miss" => @uid_cache_misses.to_s,
      "Jobs_Cache_miss" => @jobs_cache_misses.to_s,
    }
  end
  def get_db_job_info(id : UInt32) : NamedTuple(user: String, account: String) | Nil
    uid = nil
    account = nil
    @db_database.using_connection do |db|
      uid, account = db.query_one("SELECT id_user, account FROM #{@db_table} WHERE id_job=?", id.to_i32, as: {Int32, String | Nil})
    end
    if uid.nil?
      STDERR.puts "DB couldn't find information for jobid: #{id}"
      @jobs_cache_misses += 1
      nil
    else
      if (account.nil? || account.empty?)
        account = if uid == 0
            "root"
          else
            STDERR.puts "UID found but account empty for jobid: #{id}"
            ""
          end
      end 
      user = get_username_from_uid(uid.to_s)
      if user.nil?
        nil
      else
        {user: user, account: account}
      end
    end
  end
  def get_jobs_info(id : UInt32) : NamedTuple(user: String, account: String) | Nil
    if ! @jobs_cache.has?(id)
      @jobs_mutex.synchronize do
        if ! @jobs_cache.has?(id)
          @jobs_cache_misses += 1
          user_account = get_db_job_info(id)
          if user_account.nil?
            @jobs_cache.set(id, nil, Time.utc + 45.second)
          else
            @jobs_cache.set(id, user_account)
            return user_account
          end
          STDERR.puts "Jobs cache miss but shouldn't have: #{id}" if ! @jobs_cache.has?(id)
        end
      end
    end
    @jobs_cache.get(id)
  end
  def get_username_from_uid(uid : String)
    if ! @uid_cache.has?(uid)
      @uid_mutex.synchronize do
        if ! @uid_cache.has?(uid)
          @uid_cache_misses += 1
          cache_username_info(uid)
        end
      end
    end
    @uid_cache.get(uid)
  end
  def cache_username_info(uid : String)
    username = get_username(uid)
    if username.nil? || username.empty?
      @uid_cache.set(uid,username, Time.utc + 3.hour)
      STDERR.puts "Username nil|empty: #{uid}"
    else
      @uid_cache.set(uid,username)
    end
    #@uid_cache.set(uid,username) if username
  end
  def get_username(uid : String) : String
    return "root" if uid == "0"
  
    filter = LDAP::Request::Filter.equal("uidNumber", uid)
    result = @ldap_client.search(base: @search_base, filter: filter, attributes: ["uid"])
    begin
      uid_mem = IO::Memory.new(result[0]["uid"][0])
      uid_mem.set_encoding("UTF-8", invalid: :skip)
      return uid_mem.gets_to_end
    rescue IndexError
      STDERR.puts "Unable to find user in LDAP, UID: #{uid}\nResult: #{result.inspect}"
      return ""
    end
    return ""
  end
  def improve_metric(metric : String) String
      if m1 = %r<^(lustre_job[^{]+){([^}]+)} (.+)$>.match(metric)
        metric_name = m1[1]
        labels_d = {} of String => String
        m1[2].scan(%r{([^\=,]+?)="([^\"]+?)"}) do |matched|
          labels_d[matched[1]] = matched[2]
        end
        metric_value = m1[3]
  
        if labels_d["jobid"]?
          if jobid = labels_d["jobid"].to_u32?
            if ! (jobid_data = get_jobs_info(jobid)).nil?
              labels_d["user"] = jobid_data[:user]
              labels_d["account"] = jobid_data[:account]
            end
          else
            # login node or mgmt node with procname.uid
            if m3 = %r{^(.*)\.(\d+)$}.match(labels_d["jobid"])
              labels_d["application"] = m3[1] if m3[1]?
              if m3[2]?
                if (username = get_username_from_uid(m3[2]))
                  labels_d["user"] = username
                end
              end
            end
          end
          sub_pairs = labels_d.map do |k,v|
            %(#{k}=\"#{v}\")
          end.join(",")
          if sub_pairs.nil? || sub_pairs.empty?
            metric
          else
            %(#{metric_name}{#{sub_pairs}} #{metric_value})
          end
        else
          metric
        end
      else
        metric
      end
  end
end
#Kemal.config.extra_options do |parser|
#  parser.on("--cedarpower=PATH_TO_CEDARPOWER", "Path to cedarpower program, including arguments") { |name| cedarpower_arg = name }
#end
TRUEVALS = ["y","true","yes"]
def true?(bool)
  TRUEVALS.any? {|val| val == bool.to_s.downcase }
end

config_hsh = if File.exists?("config.ini")
  INI.parse(File.read("config.ini"))
end
if config_hsh.nil?
  STDERR.puts "Must have config.ini setup in the working directory"
  exit 1
end

lustre_exporter_slurm = Lustre_exporter_slurm.new(
    ldap_host:   config_hsh["ldap"]["server"],
    ldap_port:   config_hsh["ldap"]["port"].to_i,
    ldap_ssl:    true?(config_hsh["ldap"]["ssl"]),
    ldap_tls:    true?(config_hsh["ldap"]["start_tls"]),
    search_base: config_hsh["ldap"]["search_base"],
    db_host:     config_hsh["slurmdb"]["host"],
    db_port:     config_hsh["slurmdb"]["port"].to_i,
    db_user:     config_hsh["slurmdb"]["user"],
    db_pass:     config_hsh["slurmdb"]["password"],
    db_name:     config_hsh["slurmdb"]["dbname"],
    db_table:    config_hsh["slurmdb"]["job_table"],
  )

Kemal.run(port: config_hsh["api"]["local_port"].to_i, args: ARGV) do |config|
  serve_static false

  get "/:server" do |env|
    server = env.params.url["server"]
    env.response.content_type = "text/plain"
    # Protect from mal-formed requests
    server = URI.encode_www_form(server)
    HTTP::Client.get("http://#{server}:9169/metrics") do |response|
      if response.success?
        response.body_io.each_line do |line|
          env.response.puts lustre_exporter_slurm.improve_metric(line)
        end
      else
        halt env, status_code: response.status_code, response: response.status_message
      end
    end
    ""
  end
  get "/stats" do |env|
    env.response.content_type = "text/plain"
    env.response.puts lustre_exporter_slurm.get_stats
    ""
  end
end
lustre_exporter_slurm.close
