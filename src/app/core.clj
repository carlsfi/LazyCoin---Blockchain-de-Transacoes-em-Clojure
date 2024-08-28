;; $$$                                  .d$$$$b.           d$b          
;; $$$                                 d$$P  Y$$b          Y$P          
;; $$$                                 $$$    $$$                       
;; $$$       $$$$b.  $$$$$$$$ $$$  $$$ $$$         .d$$b.  $$$ $$$$$b.  
;; $$$          "$$b    d$$P  $$$  $$$ $$$        d$$""$$b $$$ $$$ "$$b 
;; $$$      .d$$$$$$   d$$P   $$$  $$$ $$$    $$$ $$$  $$$ $$$ $$$  $$$ 
;; $$$      $$$  $$$  d$$P    Y$$b $$$ Y$$b  d$$P Y$$..$$P $$$ $$$  $$$ 
;; $$$$$$$$ "Y$$$$$$ $$$$$$$$  "Y$$$$$  "Y$$$$P"   "Y$$P"  $$$ $$$  $$$ 
;;                                 $$$                                  
;;                            Y$b d$$P                                  
;;                             "Y$$P"                                    

;; Feito por José Carlos Magalhães, Pedro Cabral.
;; Programação Funcional - Prof. Gilson Pereira.

(ns app.core

  (:require
    ;; Built-ins do Clojure.
    [clojure.data.json :as json]
    [clojure.java.io :as io]
    [clojure.string :as str]
    [ring.adapter.jetty :refer [run-jetty]]
    [ring.util.request :refer [body-string]]
    [ring.util.codec :refer [form-decode]])

  (:import
    ;; Interoperabilidade com Java.
    (java.security MessageDigest KeyPairGenerator KeyFactory Signature)
    (java.security.interfaces RSAPublicKey RSAPrivateKey)
    (java.security.spec RSAPublicKeySpec RSAPrivateKeySpec)
    (javax.crypto Cipher)
    (java.util Base64)
    (java.nio.charset StandardCharsets)))

;;   ___                 _ _           
;;  | __|_ _  __ ___  __| (_)_ _  __ _ 
;;  | _|| ' \/ _/ _ \/ _` | | ' \/ _` |
;;  |___|_||_\__\___/\__,_|_|_||_\__, |
;;                               |___/ 

(defn b64-encode [input]
  "Codifica uma string ou bytes para uma string Base64."
  (let [bytes (if (string? input) (.getBytes input StandardCharsets/UTF_8) input)]
    (.encodeToString (Base64/getEncoder) bytes)))

(defn b64-into-bytes [str]
  "Decodifica uma string Base64 para bytes."
  (.decode (Base64/getDecoder) str))

(defn b64-into-str [str]
  "Decodifica uma string Base64 para uma string UTF-8."
  (let [bytes (b64-into-bytes str)]
    (String. bytes StandardCharsets/UTF_8)))

;;    ___               _       
;;   / __|_ _ _  _ _ __| |_ ___ 
;;  | (__| '_| || | '_ \  _/ _ \
;;   \___|_|  \_, | .__/\__\___/
;;            |__/|_|           

(defn keypair-generator [length]
  "Retorna um gerador de chaves assimétricas RSA."
  ;; Adaptado de: https://worace.works/2016/06/05/rsa-cryptography-in-clojure/
  (doto (KeyPairGenerator/getInstance "RSA") (.initialize length)))

(defn generate-keypair []
  "Gera um par de chaves assimétricas RSA."
  ;; Adaptado de: https://worace.works/2016/06/05/rsa-cryptography-in-clojure/
  (.generateKeyPair (keypair-generator 512)))

(defn encrypt [message public-key]
  "Criptografa uma string utilizando RSA + Chave Pública."
  ;; Adaptado de: https://worace.works/2016/06/05/rsa-cryptography-in-clojure/
  (b64-encode
    (let [cipher (doto (Cipher/getInstance "RSA/ECB/PKCS1Padding") (.init Cipher/ENCRYPT_MODE public-key))]
    (.doFinal cipher (.getBytes message)))))

(defn decrypt [message private-key]
  "Descriptografa uma string utilizando RSA + Chave Privada."
  ;; Adaptado de: https://worace.works/2016/06/05/rsa-cryptography-in-clojure/
  (let [cipher (doto (Cipher/getInstance "RSA/ECB/PKCS1Padding") (.init Cipher/DECRYPT_MODE private-key))]
    (->> message b64-into-bytes (.doFinal cipher) (map char) (apply str))))

(defn sign [message private-key]
  "Produz uma assinatura de uma chave RSA da mensagem e chave privada."
  ;; Adaptado de: https://worace.works/2016/06/05/rsa-cryptography-in-clojure/
  (b64-encode
   (let [msg-data (.getBytes message)
         sig (doto (Signature/getInstance "SHA256withRSA") (.initSign private-key (java.security.SecureRandom.)) (.update msg-data))]
         (.sign sig))))

(defn verify [encoded-sig message public-key]
  "Verifica se uma assinatura RSA corresponde à chave pública."
  ;; Adaptado de: https://worace.works/2016/06/05/rsa-cryptography-in-clojure/
  (let [msg-data (.getBytes message)
        signature (b64-into-bytes encoded-sig)
        sig (doto (Signature/getInstance "SHA256withRSA") (.initVerify public-key) (.update msg-data))]
        (.verify sig signature)))

(defn sha-256 [input]
  "Retorna a hash SHA-256 em forma hexadecimal."
  ;; Adaptado de: https://gist.github.com/kisom/1698245
  (let [hash (MessageDigest/getInstance "SHA-256")]
        (. hash update (.getBytes input))
        (let [digest (.digest hash)]
              (apply str (map #(format "%02x" (bit-and % 0xff)) digest)))))

(defn key-to-str [key]
  "Transforma uma chave pública ou privada em uma string Base64."
  (let [modulus (.getModulus key)
        exponent (if (instance? RSAPublicKey key) (.getPublicExponent key) (.getPrivateExponent key))]
    (b64-encode (str modulus "^" exponent))))

(defn str-to-mod-exp [key]
  "Transforma uma string Base64 em um objeto intermediário."
  (try (let [decoded (b64-into-str key)
          split-decoded (clojure.string/split decoded #"\^")]
      (if (= 2 (count split-decoded))
        (let [[modulus exponent] split-decoded]
          {:modulus (BigInteger. modulus 10)
           :exponent (BigInteger. exponent 10)}) nil))
    (catch IllegalArgumentException e nil)))

(defn str-to-key [key type]
  "Transforma uma string Base64 em uma chave RSA, sendo `type` :public ou :private."
  (let [key-map (str-to-mod-exp key)]
    (if key-map (let [modulus (:modulus key-map) exponent (:exponent key-map) key-factory (KeyFactory/getInstance "RSA")]
        (case type
          :public  (.generatePublic key-factory (RSAPublicKeySpec. modulus exponent))
          :private (.generatePrivate key-factory (RSAPrivateKeySpec. modulus exponent))))
      nil)))

(defn valid-keypair? [public-key private-key]
  "Verifica se a chave pública e privada formam um par de chaves RSA válido."
  (let [test-message "Message"
        signature (sign test-message private-key)]
    (verify signature test-message public-key)))

(defn valid-str-keypair? [public-key-str private-key-str]
  "Verifica se a string de chave pública e privada formam um par de chaves RSA válido."
  (try
    (let [public-key (str-to-key public-key-str :public)
          private-key (str-to-key private-key-str :private)]
      (valid-keypair? public-key private-key))
    (catch Exception e false)))

;;   ___              _           
;;  | _ \__ _ _ _  __| |___ _ __  
;;  |   / _` | ' \/ _` / _ \ '  \ 
;;  |_|_\__,_|_||_\__,_\___/_|_|_|

(defn random-id [length]
  "Produz um identificador aleatório [A-z0-9] de `length` dígitos."
  (apply str (take length (repeatedly #(rand-nth (str/join (concat (map char (range 48 58)) (map char (range 65 91)) (map char (range 97 123)))))))))

;;   ___       _        
;;  |   \ __ _| |_ __ _ 
;;  | |) / _` |  _/ _` |
;;  |___/\__,_|\__\__,_|

;; Esta é a blockchain.
(def blockchain (atom {}))

;; Estas são as alterações atuais que serão mineradas na blockchain.
(def pending (atom []))

;; Esta booleana atômica diz se há uma mineração em curso (ou não).
(def mining-in-progress (atom false))

;;    ___ _         _      ___          
;;   / __| |_  __ _(_)_ _ / _ \ _ __ ___
;;  | (__| ' \/ _` | | ' \ (_) | '_ (_-<
;;   \___|_||_\__,_|_|_||_\___/| .__/__/
;;                             |_|      

(defn hash-block [block]
  "Computa a hash do bloco."
  (let [block-as-str (str (:number block) (:nonce block) (json/write-str (:data block)) (:previous block))]
    (sha-256 block-as-str)))

(defn get-block [key]
  "Obtém um bloco da blockchain (retorna `nil` caso não exista)."
  (@blockchain key))

(defn get-last-block []
  "Retorna o último bloco da blockchain."
  (last (sort-by :number (vals @blockchain))))

(defn get-chain-numbers []
  "Retorna todos os números dos blocos."
  (sort (map #(Integer/parseInt (str/replace (str %) #":" "")) (keys @blockchain))))

(defn get-next-block-number []
  "Obtém o número do próximo bloco que será minerado da blockchain."
  (if (empty? @blockchain)
    0
    (inc (apply max (get-chain-numbers)))))

(defn add-block [block]
  "Adiciona um bloco à blockchain."
  (swap! blockchain assoc (get-next-block-number) block))

(defn add-pending [transaction]
  "Adiciona uma operação como pendente."
  (swap! pending conj transaction))

(defn track-wallet [address]
  "Retorna todas as transações já feitas pela carteira."
  (let [blocks (vals @blockchain)
        transactions (concat (mapcat :data blocks) @pending)]
        (filter #(or (= (:wallet %) address) (= (:from %) address) (= (:to %) address)) transactions)))

(defn wallet-exists? [address]
  "Verifica se a carteira (endereço) existe na blockchain."
  (>= (count (track-wallet address)) 1))

(defn compute-wallet-balance [address]
  "Calcula o saldo da carteira com base nas transações da blockchain e das alterações pendentes."
  (let [transactions (track-wallet address)]
        (reduce (fn [acc tx]
          (cond
            (= (:wallet tx) address) (+ acc (:amount tx))
            (= (:to tx) address) (+ acc (:amount tx))
            (= (:from tx) address) (- acc (:amount tx))
            :else acc)) 0 transactions)))

(defn all-wallets []
  "Retorna uma lista de todas as carteiras."
  (let [blocks (vals @blockchain)
        transactions (concat (mapcat :data blocks) @pending)
        ;; https://clojuredocs.org/clojure.set
        addresses (reduce (fn [acc tx] (conj acc (:wallet tx))) #{} transactions)]
    (remove nil? (seq addresses))))

(defn track-transaction [id]
  "Retorna uma transação com o dado identificador."
  (let [blocks (vals @blockchain)
        transactions (concat (mapcat :data blocks) @pending)]
    (first (filter #(= (:id %) id) transactions))))

;;   ___               __          __   __      __       _   
;;  | _ \_ _ ___  ___ / _|___ ___ / _|__\ \    / /__ _ _| |__
;;  |  _/ '_/ _ \/ _ \  _|___/ _ \  _|___\ \/\/ / _ \ '_| / /
;;  |_| |_| \___/\___/_|     \___/_|      \_/\_/\___/_| |_\_\

(defn valid-proof? [block]
  "Retorna `true` caso a proof-of-work (nonce) seja válida."
  (-> (hash-block block)
      (str/starts-with? "0000"))) ;; Dificuldade

(defn proof-of-work [base-block]
  "Retorna o bloco minerado com a `nonce` que é a proof-of-work."
  (loop [nonce 0
         block (assoc base-block :nonce 0)]
    (if (valid-proof? block)
      block (recur (inc nonce) (assoc block :nonce (inc nonce))))))

(defn mine-block []
  "Minera o novo bloco e reinicia as mudanças pendentes."
  (let [previous-block (get-last-block)
        previous-hash (if previous-block (hash-block previous-block) "0000000000000000000000000000000000000000000000000000000000000000")
        new-block {:number (get-next-block-number) :previous previous-hash :data @pending :nonce ""}
        mined-block (proof-of-work new-block)]

    ;; Adiciona o novo bloco na blockchain.
    (add-block (assoc mined-block :hash (hash-block mined-block)))

    ;; Reinicia as mudanças pendentes.
    (reset! pending [])))

;;   ___            _   ___         _ 
;;  | __| _ ___ _ _| |_| __|_ _  __| |
;;  | _| '_/ _ \ ' \  _| _|| ' \/ _` |
;;  |_||_| \___/_||_\__|___|_||_\__,_|

(defn index-route [request]
  "[GET] / — Retorna a página principal em HTML."
  (let [index (io/file "resources/blockchain.html")]
    {:status 200
     :headers {"Content-Type" "text/html; charset=utf-8"}
     :body index}))

(defn mine-route [request]
  "[GET] / — Retorna a página principal em HTML."
  (let [index (io/file "resources/mine.html")]
    {:status 200
     :headers {"Content-Type" "text/html; charset=utf-8"}
     :body index}))

(defn create-wallet-route [request]
  "[GET] /wallet/? — Retorna a página de criação de carteiras em HTML."
  (let [index (io/file "resources/wallet.html")]
    {:status 200
     :headers {"Content-Type" "text/html; charset=utf-8"}
     :body index}))

(defn transfer-route [request]
  "[GET] /transfer/? — Retorna a página de transferência em HTML."
  (let [index (io/file "resources/transfer.html")]
    {:status 200
     :headers {"Content-Type" "text/html; charset=utf-8"}
     :body index}))

(defn track-wallet-route [request]
  "[GET] /wallet/? — Retorna a página de consulta de carteira em HTML."
  (let [index (io/file "resources/track.html")]
    {:status 200
     :headers {"Content-Type" "text/html; charset=utf-8"}
     :body index}))

(defn transaction-route [request]
  "[GET] /transaction/? — Retorna a página de consulta de transferência em HTML."
  (let [index (io/file "resources/transaction.html")]
    {:status 200
     :headers {"Content-Type" "text/html; charset=utf-8"}
     :body index}))

;;   ___          _          
;;  | _ \___ _  _| |_ ___ ___
;;  |   / _ \ || |  _/ -_|_-<
;;  |_|_\___/\_,_|\__\___/__/

(defn get-chain-route [request]
  "[GET] /chain — Retorna toda a blockchain."
  {:status 200
   :headers {"Content-Type" "text/json; charset=utf-8"}
   :body (json/write-str @blockchain)})

(defn get-pending-route [request]
  "[GET] /pending — Retorna toda a pool de transações que estão pendentes para serem mineradas."
  {:status 200
   :headers {"Content-Type" "text/json; charset=utf-8"}
   :body (json/write-str @pending)})

(defn get-block-number-route [request]
  "[GET] /block/:number — Retorna um bloco específico da blockchain."
  (let [uri (:uri request)
        id (keyword (nth (re-find #"/block/(.+)/?" uri) 1))
        block (get-block id)]

        ;; Verifique se o bloco existe..
        (if block
          
          ;; Caso o bloco exista, retorne-o.
          {:status 200
           :headers {"Content-Type" "text/json; charset=utf-8"}
           :body (json/write-str block)}

          ;; Caso o bloco não exista, retorne 404.
          {:status 404
           :headers {"Content-Type" "text/json; charset=utf-8"}
           :body (json/write-str {:status 404 :message "O bloco não existe."})})))

(defn get-transaction-id-route [request]
  "[GET] /transaction/:id/? — Retorna uma transação específica da blockchain."
  
  (let [uri (:uri request)
        transaction (nth (re-matches #"/transaction/([^/]+)/?" uri) 1)]

    (if (track-transaction transaction)
    
      ;; Retorne a transação.
      {:status 200
       :headers {"Content-Type" "text/json; charset=utf-8"}
       :body (json/write-str (track-transaction transaction))}

      ;; A transação não foi encontrada.
      {:status 404
       :headers {"Content-Type" "text/json; charset=utf-8"}
       :body (json/write-str {:status 404 :body "Transação não encontrada."})})))

(defn get-wallets-route [request]
  "[GET] /wallets/? — Retorna uma lista de todas as carteiras na blockchain."
  {:status 200
   :headers {"Content-Type" "text/json; charset=utf-8"}
   :body (json/write-str (all-wallets))})

(defn get-wallet-id-route [request]
  "[GET] /wallet/? — Retorna uma carteira com seu saldo na blockchain."
  (let [uri (:uri request)
        wallet (nth (re-matches #"/wallet/([^/]+)/?" uri) 1)]

    ;; Verifique se a carteira foi passada como parâmetro.
    (if (= wallet nil)

      ;; Ignore a requisição.
      {:status 400
       :headers {"Content-Type" "text/json; charset=utf-8"}
       :body (json/write-str {:status 400 :body "Uma carteira precisa ser fornecida como parâmetro."})}

      ;; Verifique se a carteira existe.
      (if (wallet-exists? wallet)
      
        ;; Retorne as informações da carteira.
        {:status 200
        :headers {"Content-Type" "text/json; charset=utf-8"}
        :body (json/write-str
            {:status 200
             :balance (compute-wallet-balance wallet)
             :transactions (track-wallet wallet)})}

        ;; Retorne uma mensagem dizendo que a carteira não foi encontrada.
        {:status 404
        :headers {"Content-Type" "text/json; charset=utf-8"}
        :body (json/write-str {:status 404 :message "Carteira não encontrada."})}))))

(defn post-wallet-route [request]
  "[POST] /wallet — Cria uma carteira na blockchain."
  (let [keypair (generate-keypair)
        public (.getPublic keypair)
        private (.getPrivate keypair)]

    ;; Adicione à carteira à blockchain.
    (add-pending {:wallet (key-to-str public) :amount (if (= (get-next-block-number) 0) 10 0)})

    ;; Retorne o JSON com o par de chaves.
    {:status 200
     :headers {"Content-Type" "text/json; charset=utf-8"}
     :body (json/write-str
       {:public-key (key-to-str public)
        :private-key (key-to-str private)})}))

(defn post-mine-route [request]
  "[POST] /mine — Minera as transações pendentes na blockchain."

  ;; Verifique se já há uma mineração em progresso.
  (if (not (compare-and-set! mining-in-progress false true))
    
    ;; Se uma mineração estiver em progresso, retorne "409 - Conflict".
    {:status 409
     :headers {"Content-Type" "text/json; charset=utf-8"}
     :body (json/write-str {:status 409 :message "Uma mineração já está em andamento."})}

    ;; Caso contrário, prossiga com a mineração.
    (try

      ;; Se não houverem transações pendentes, não minere-a.
      (if (empty? @pending)

        ;; Retorne "422 - Unprocessable Entity".
        {:status 422
         :headers {"Content-Type" "text/json; charset=utf-8"}
         :body (json/write-str {:status 422 :message "Sem transações pendentes."})}
      
        (do

          ;; Minere a blockchain.
          (mine-block)

          ;; Retorne "200 - OK" com as informações do último bloco.
          {:status 200
           :headers {"Content-Type" "text/json; charset=utf-8"}
           :body (json/write-str
                  {:status 200
                   :message (str "Block #" (:number (get-last-block)) " mined successfully.")
                   :nonce (:nonce (get-last-block))
                   :hash (:hash (get-last-block))})}))
      
      (finally

        ;; Certifique-se de liberar o bloqueio de mineração.
        (reset! mining-in-progress false)))))

(defn post-transfer-route [request]
  "[POST] /transfer — Transfere uma quantidade de uma carteira para outra."
  (let [body (json/read-str (body-string request) :key-fn keyword)
        public-key (:public-key body)
        private-key (:private-key body)
        target-key (:target-key body)
        amount (:amount body)]

    ;; Verifique se algum valor é nulo.
    (if (or (= public-key nil) (= private-key nil) (= target-key nil) (= amount nil))

      ;; Ignore a requisição.
      {:status 400
       :headers {"Content-Type" "text/json; charset=utf-8"}
       :body (json/write-str {:status 400 :message "Nem todos os parâmetros obrigatórios foram fornecidos."})}
    
      ;; Verifique se a carteira de origem e destinatária existem.
      (if (not (and (wallet-exists? target-key) (wallet-exists? public-key)))
      
        ;; Ignore a requisição.
        {:status 400
         :headers {"Content-Type" "text/json; charset=utf-8"}
         :body (json/write-str {:status 400 :message "A carteira de origem ou a carteira destinatária não existem."})}

        ;; Verifique se a chave de origem e a chave de destino são a mesma.
        (if (= public-key target-key)

          ;; Ignore a requisição.
          {:status 400
           :headers {"Content-Type" "text/json; charset=utf-8"}
           :body (json/write-str {:status 400 :message "As chaves de origem e destinatária não podem ser a mesma."})}

          ;; Verifique se a chave pública e privada fornecida formam um par válido.
          (if (not (valid-str-keypair? public-key private-key))

            ;; Ignore a requisição.
            {:status 400
            :headers {"Content-Type" "text/json; charset=utf-8"}
            :body (json/write-str {:status 400 :message "As suas chaves pública e privada fornecidas não correspondem."})}

            ;; Verifique se o valor a ser passado é maior ou igual a 1.
            (if (<= (int amount) 0)

              ;; Ignore a requisição.
              {:status 400
               :headers {"Content-Type" "text/json; charset=utf-8"}
               :body (json/write-str {:status 400 :message "O valor a ser transferido deve ser um inteiro maior do que zero."})}

              ;; Verifique se é possível fazer a transferência.
              (if (< (- (compute-wallet-balance public-key) (int amount)) 0)
                  
                ;; Ignore a requisição.
                {:status 400
                  :headers {"Content-Type" "text/json; charset=utf-8"}
                  :body (json/write-str {:status 400 :message "Saldo insuficiente."})}
                
                (let [transaction-id (random-id 32)]
                
                  ;; Realize a transferência entre as duas carteiras.
                  (add-pending {:id transaction-id :from public-key :to target-key :amount (int amount) :sign
                    (sign (json/write-str {:id transaction-id :from public-key :to target-key :amount amount}) (str-to-key private-key :private))})
                  
                  ;; Retorne a resposta.
                  {:status 200
                    :headers {"Content-Type" "text/json; charset=utf-8"}
                    :id transaction-id
                    :body (json/write-str {:status 200 :message "Transação realizada com sucesso."})})))))))))

;;   ___          _           
;;  | _ \___ _  _| |_ ___ _ _ 
;;  |   / _ \ || |  _/ -_) '_|
;;  |_|_\___/\_,_|\__\___|_|  

(def routes {
  
  ;; Todas as rotas de interface (front-end).
  [:get #"/"]                      index-route
  [:get #"/mine/?"]                mine-route
  [:get #"/track/?"]               track-wallet-route
  [:get #"/wallet/?"]              create-wallet-route
  [:get #"/transfer/?"]            transfer-route
  [:get #"/transaction/?"]         transaction-route
  
  ;; Todas as rotas "informacionais" [GET].
  [:get #"/wallets/?"]             get-wallets-route
  [:get #"/chain/?"]               get-chain-route
  [:get #"/pending/?"]             get-pending-route
  
  ;; Todas as rotas com parâmetros na URL [GET].
  [:get #"/transaction/([^/]+)/?"] get-transaction-id-route
  [:get #"/block/([^/]+)/?"]       get-block-number-route
  [:get #"/wallet/([^/]+)/?"]      get-wallet-id-route
  
  ;; Todas as rotas de modificação [POST].
  [:post #"/wallet/?"]             post-wallet-route
  [:post #"/mine/?"]               post-mine-route
  [:post #"/transfer/?"]           post-transfer-route

})

(defn route-matches? [input-method pattern request]
  "Retorna `true` caso o método HTTP e URI corresponderem à rota."
  (let [uri (:uri request) method (:request-method request)]
        (and (= input-method method) (re-matches pattern uri))))

(defn router [request]
  "Este é o roteador de endpoints do servidor (higher-order function)."
  (let [method (:request-method request) uri (:uri request)]
        
        ;; Aqui a `route` é extraída.
        (if-let [route (some (fn [[k v]] (when
          (route-matches? (first k) (second k) request) v)) routes)]
        
                ;; Envie a requisição para a rota adequada.
                (route request)
                
                ;; Caso contrário, envie um erro 404.
                {:status 404
                 :headers {"Content-Type" "text/json; charset=utf-8"}
                 :body (json/write-str {:message "Não encontrado." :status 404})})))

(defn -main []
  ;; Faça o servidor HTTP escutar requisições pela porta 8080.
  (run-jetty router {:port 8080 :join? false}))