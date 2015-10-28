package tests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/tests/testapi"
)

var formPage = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">

  <title>Keyless Tester</title>
  <link href='//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.4/css/bootstrap.min.css' rel='stylesheet prefetch'>
  <style>
  body {
      padding-top: 30px;
    }
  </style>
</head>

<body>
  <div class="container">
    <h1 class="page-header">Keyless Tester</h1>
    <div class="row">
      <div class="col-md-8 col-md-offset-2">
        <form class="form-horizontal" id="keyserver-test" name="keyserver-test">
          <label for="keyserver">Keyserver</label>
          <input class="form-control" name="keyserver" placeholder="keyserver:port" type="text">
          <label for="domain">Domain (optional)</label>
          <input class="form-control" name="domain" placeholder="example.com" type="text">
          <label for="cf_ip">CloudFlare IP (optional)</label>
          <input class="form-control" name="cf_ip" placeholder="198.41.215.163" type="text">
          <label for="certs">Certificate(s) (optional)</label>
          <textarea class="form-control" name="certs" placeholder="Paste PEM certificate" class="width-full" rows="25"></textarea>
          <label for="testlen">Test Length</label><input type="text" name="testlen" value="%s">
          <label for="workers">Num Workers</label><input type="number" name="workers" min="1" max="1024" value="%d">
          <label><input name="insecure_skip_verify" type="checkbox">Insecure Skip Verify</label>
        <button class="btn btn-primary" style="float: right;" type="submit">Scan</button>
      </form>
    </div>
  </div>

  <div class="row">
    <div class="col-md-8 col-md-offset-2">
      <pre id="results" style="display: none"></pre>
    </div>
  </div>

  <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
  <script>
    $("#keyserver-test").submit(function(event) {
      event.preventDefault();
      $("#results").hide();
      var input = {};
      $($("#keyserver-test").serializeArray()).each(function(i, field) {
        input[field.name] = (field.value === "on") ? true : field.value;
      });
      var formData = JSON.stringify(input);
      console.log("input: " + formData);
      $.post("/", formData, function(data) {
      	  $("#results").empty()
          $("#results").show();
          console.log(data);
          $("#results").text(JSON.stringify(data, null, 2));
      }, "json").fail(function(error) {
          $("#results").empty()
          $("#results").show();
          console.log(error);
          $("#results").html("<div class='alert alert-danger'>"+error.responseText+"</div>");
      });
      console.log("Form Posted");
    });
  </script>
</body>
</html>
`

type apiHandler struct {
	c       *client.Client
	testLen time.Duration
	workers int
}

func (api *apiHandler) ServeFormPage(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, formPage, api.testLen, api.workers)
}

func (api *apiHandler) ServeFormResponse(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	in := new(testapi.Input)
	if err := json.Unmarshal(body, in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results, err := RunAPITests(in, api.c, api.testLen, api.workers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (api *apiHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		api.ServeFormPage(w, req)
		return
	case "POST":
		api.ServeFormResponse(w, req)
	default:
		http.Error(w, "405 Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

// ListenAndServeAPI creates an HTTP endpoint at addr.
func ListenAndServeAPI(addr string, testLen time.Duration, workers int, c *client.Client) error {
	log.Infof("Serving Tester API at %s/\n", addr)

	http.Handle("/", &apiHandler{c, testLen, workers})
	return http.ListenAndServe(addr, nil)
}
