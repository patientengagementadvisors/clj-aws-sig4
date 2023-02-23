(ns pea.aws.aws-sig4-test
  (:require [clojure.test :refer :all]
            [pea.aws.aws-sig4 :refer :all]))

; 'import' 'private' functions so we can test them.
(def create-normalized-map #'pea.aws.aws-sig4/create-normalized-map)
(def create-canonical-request #'pea.aws.aws-sig4/create-canonical-request)
(def create-string-to-sign #'pea.aws.aws-sig4/create-string-to-sign)
(def create-signing-key #'pea.aws.aws-sig4/create-signing-key)
(def create-signature #'pea.aws.aws-sig4/create-signature)
(def create-auth-value #'pea.aws.aws-sig4/create-auth-value)

; https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

; this is the GET example from here: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
; Their sample canonical-request had 2 spaces at the end when using their copy text button.

(deftest test-create-canonical-request-GET-sample
  (def raw-map {"x-amz-content-sha256" (hash-hex "")
                "HOST" "examplebucket.s3.amazonaws.com"
                "x-amz-date" "20130524T000000Z"
                "Range" "bytes=0-9"})

  (def normalize-map (create-normalized-map raw-map))
  (def sorted-keys (sort (keys normalize-map)))

  (def canon-req1 (create-canonical-request "GET" "/test.txt" "" sorted-keys normalize-map))

  (is (= "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" canon-req1))
  (is (= "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972" (hash-hex canon-req1))))


(deftest test-create-normalized-map
  (is (= {"key1" "value1", "key2" "value2", "key-3" "value3"} (create-normalized-map {:Key1 "value1" "key2" "value2" "KEY-3" "value3"}))))

(deftest test-body-hash
  (is (= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (hash-hex "")))
  (is (= "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" (hash-hex "Welcome to Amazon S3."))))


(deftest test-create-string-to-sign-GET-example
  (def date-str "20130524T000000Z")
  (def raw-map {"x-amz-content-sha256" (hash-hex "")
                "HOST" "examplebucket.s3.amazonaws.com"
                "x-amz-date" date-str
                "Range" "bytes=0-9"})

  (def normalize-map (create-normalized-map raw-map))
  (def sorted-keys (sort (keys normalize-map)))

  (def canon-req1 (create-canonical-request "GET" "/test.txt" "" sorted-keys normalize-map))

  (def string-to-sign (create-string-to-sign canon-req1 date-str "us-east-1" "s3"))
  (is (= "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972" string-to-sign)))


(deftest test-create-create-singing-key-and-create-signature-GET-example
  (def aws-key "AKIAIOSFODNN7EXAMPLE")
  (def aws-secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

  (def date-str "20130524T000000Z")
  (def date-prefix "20130524")
  (def raw-map {"x-amz-content-sha256" (hash-hex "")
                "HOST" "examplebucket.s3.amazonaws.com"
                "x-amz-date" date-str
                "Range" "bytes=0-9"})

  (def normalize-map (create-normalized-map raw-map))
  (def sorted-keys (sort (keys normalize-map)))

  (def canon-req1 (create-canonical-request "GET" "/test.txt" "" sorted-keys normalize-map))

  (def string-to-sign (create-string-to-sign canon-req1 date-str "us-east-1" "s3"))

  (def sig-key-bytes (create-signing-key aws-secret "20130524" "us-east-1" "s3"))
  (def signature (create-signature sig-key-bytes string-to-sign))
  (is (= "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" signature)))


(deftest test-create-auth-value-GET-example
  (def aws-key "AKIAIOSFODNN7EXAMPLE")
  (def aws-secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
  (def region "us-east-1")
  (def service "s3")
  (def date-str "20130524T000000Z")
  (def date-prefix "20130524")
  (def http-verb "GET")
  (def uri "/test.txt")
  (def query-string "")

  (def headers {"x-amz-content-sha256" (hash-hex "")
                "host" "examplebucket.s3.amazonaws.com"
                "x-amz-date" date-str
                "range" "bytes=0-9"})

  (def sorted-keys (sort (keys headers)))

  (def canonical-request (create-canonical-request http-verb uri query-string sorted-keys headers))

  (def string-to-sign (create-string-to-sign canonical-request date-str region service))

  (def sig-key-bytes (create-signing-key aws-secret date-prefix region service))
  (def signature (create-signature sig-key-bytes string-to-sign))

  (is (= "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
         (create-auth-value aws-key date-prefix region service sorted-keys signature))))

(deftest test-PUT-example
  (def aws-key "AKIAIOSFODNN7EXAMPLE")
  (def aws-secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

  (def http-verb "PUT")
  (def host "examplebucket.s3.amazonaws.com")
  (def date "Fri, 24 May 2013 00:00:00 GMT")
  (def content "Welcome to Amazon S3.")
  (def uri "/test%24file.text")
  (def x-amz-date "20130524T000000Z")
  (def date-prefix "20130524")
  (def region "us-east-1")
  (def service "s3")

  (def headers {"date" date
                "host" host
                "x-amz-content-sha256" (hash-hex content)
                "x-amz-date" "20130524T000000Z"
                "x-amz-storage-class" "REDUCED_REDUNDANCY"})
  (def sorted-keys (sort (keys headers)))

  (def canonical-request (create-canonical-request http-verb uri "" sorted-keys headers))

  (is (= "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\nx-amz-date:20130524T000000Z\nx-amz-storage-class:REDUCED_REDUNDANCY\n\ndate;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
         canonical-request))

  (def string-to-sign (create-string-to-sign canonical-request x-amz-date region service))

  (is (= "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
         string-to-sign))

  (def signing-key (create-signing-key aws-secret date-prefix region service))
  (def signature (create-signature signing-key string-to-sign))

  (is (= "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
         signature))

  (def auth-value (create-auth-value aws-key date-prefix region service sorted-keys signature))

  (is (= "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
         auth-value))

  (def authorization (create-authorization "PUT" uri "" aws-key aws-secret x-amz-date region service sorted-keys headers))
  (is (= "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
         authorization)))

