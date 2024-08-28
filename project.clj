(defproject lazy-coin "0.0.1-SNAPSHOT"
  :description "..."
  :url "..."
  :license {:name "MIT"
            :url "https://opensource.org/license/mit"}
  :dependencies [
    
    ;; ...
    [org.clojure/clojure "1.11.1"]
    [org.clojure/data.json "2.5.0"]
    [org.clojure/data.codec "0.1.1"]

    ;; ...
    [ring/ring-core "1.12.1"]
    [ring/ring-jetty-adapter "1.12.1"]

  ]
  
  :repl-options {:init-ns app.core}
  :main app.core

  )