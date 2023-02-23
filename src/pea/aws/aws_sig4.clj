(ns pea.aws.aws-sig4
  (:require [clojure.walk :as w]
            [buddy.core.hash :as hash]
            [buddy.core.mac :as mac]
            [buddy.core.codecs :as codecs]
            [clojure.string :as str]))

(defn- transform-keys
  "Recursively transform all map keys using f as a transformation function."
  [m f]
  (let [entry-f (fn [[k v]] [(f k) v])]
    ;; only apply to maps
    (w/postwalk (fn [x] (if (map? x) (into {} (map entry-f x)) x)) m)))

(defn- query-param-comp
  [[p1n p1v] [p2n p2v]]
  (let [name-order (compare p1n p2n)]
    (if (= name-order 0)
      (compare p1v p2v)
      name-order)))

(defn- create-canonical-query-string [query-string]
  (if-let [query-string query-string]
    (if-not (= "" query-string)
      (let [query-params (->> (str/split query-string #"&")
                              (map #(str/split % #"=")))]
        (if-not (empty? query-params)
          (->> query-params
               (map (fn [[name value]]
                      [name value]))
               (sort query-param-comp)
               (map #(str/join "=" %))
               (str/join "&"))
          ""))
      "")
    ""))

(defn hash-hex [^String body] (if-let [body body]
                                (-> body
                                    hash/sha256
                                    codecs/bytes->hex)
                                ""))

(defn- create-canonical-headers [keys headers]
  (str (str/join "\n" (map #(str % ":" (headers %)) keys)) "\n")) ;the last line needs a '\n' too, at the end.

;headers-being-signed
;"host;x-amz-content-sha256;x-amz-date"
(defn- create-canonical-request "This returns a string called the 'canonical request', which is used as part of the string-to-sign"
  [verb uri query-string sorted-keys headers]
  (let [headers-being-signed (str/join ";" sorted-keys)
        body-hash (or (headers "x-amz-content-sha256") "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") ;"e3b0...b855" is simply (hash-hex "")
        canonical-request (str verb "\n"
                               uri "\n"
                               (create-canonical-query-string query-string) "\n"
                               (create-canonical-headers sorted-keys headers) "\n"
                               headers-being-signed "\n"
                               body-hash)]
    canonical-request))


(defn- create-normalized-map [amap] (transform-keys amap #(.toLowerCase (name %))))

; date-str should be like '20130524T000000Z'
(defn- create-string-to-sign [canonical-request date-str region service]
  (let [date-prefix (first (str/split  date-str #"T"))]
    (str "AWS4-HMAC-SHA256" "\n"
         date-str "\n"
         (str date-prefix "/" region "/" service "/aws4_request") "\n"
         (hash-hex canonical-request))))

(defn- hmac-sha256 [key data]
  (mac/hash data {:key key :alg :hmac+sha256}))

;signing key = HMAC-SHA256( HMAC-SHA256( HMAC-SHA256( HMAC-SHA256("AWS4" + "<YourSecretAccessKey>","20130524") ,"us-east-1") ,"s3") ,"aws4_request")
(defn- create-signing-key
  [secret-key date-prefix region service]
  (-> (str "AWS4" secret-key)
      (hmac-sha256 date-prefix)
      (hmac-sha256 region)
      (hmac-sha256 service)
      (hmac-sha256 "aws4_request")))

(defn- create-signature [sig-key-bytes string-to-sign]
  (codecs/bytes->hex (hmac-sha256 sig-key-bytes string-to-sign)))

(defn- create-auth-value [aws-key date-prefix region service sorted-header-keys signature]
  (str "AWS4-HMAC-SHA256 Credential=" aws-key "/" date-prefix "/" region "/" service "/aws4_request,SignedHeaders=" (str/join ";" sorted-header-keys) ",Signature=" signature))

(defn create-authorization [http-verb uri query-string aws-key aws-secret date-str region service sorted-keys headers]
  (let [date-prefix (first (str/split date-str #"T"))
        canonical-request (create-canonical-request http-verb uri query-string sorted-keys headers)
        string-to-sign (create-string-to-sign canonical-request date-str region service)
        sig-key-bytes (create-signing-key aws-secret date-prefix region service)
        signature (create-signature sig-key-bytes string-to-sign)
        authorization (create-auth-value aws-key date-prefix region service sorted-keys signature)]
    authorization))
