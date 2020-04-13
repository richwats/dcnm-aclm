
var ACLM_API = "localhost:32768";

var LOGGED_ON = false;

// From w3schools
function getCookie(cname) {
  var name = cname + "=";
  var decodedCookie = decodeURIComponent(document.cookie);
  var ca = decodedCookie.split(';');
  for(var i = 0; i <ca.length; i++) {
    var c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return null;
}

function updateLogonMenu(){
  // Check if session cookie present
  var loggedOutMenu = $('.loggedOutMenu');
  var loggedOnMenu =$('.loggedOnMenu');
  var sessionCookie = getCookie('session');
  console.log("[updateLogonMenu] Session: "+JSON.stringify(sessionCookie))

  if (sessionCookie != null) {
    // Logged On
    loggedOnMenu.removeClass('d-none');
    loggedOutMenu.addClass('d-none');
    LOGGED_ON = true;

  }
  else {
    // Logged Off
    loggedOnMenu.addClass('d-none');
    loggedOutMenu.removeClass('d-none');
    LOGGED_ON = false;
  }
}

function loggedOn(input){
  // Logged On Successfully
  console.log("[loggedOn] "+JSON.stringify(input))

  // Update Menu
  updateLogonMenu();

  // Load Fabrics
  loadFabrics();

  // Trigger Fabric Load
  $('#selectFabricForm').submit();
}

function loggedOut(input){
  // Logged On Successfully
  console.log("[loggedOut] "+JSON.stringify(input))
  updateLogonMenu();
}

function consoleLog(input){
  console.log("[consoleLogger] "+JSON.stringify(input))
}

function loadFabrics(){
  console.log("[loadFabrics] Load Fabrics")
  resp = aclmApiWrapper("get","/fabric/listFabrics", null, buildFabricSelector)
}

function buildFabricSelector(input){
  console.log("[buildFabricSelector] Building Fabric Selector")
  console.log("[buildFabricSelector] Fabrics: "+JSON.stringify(input))
  var fabricSelector = $("#selectFabric")
  fabricSelector.empty();

  $(input).each(function(){
    //console.log("[buildFabricSelector] This: "+JSON.stringify(this))
    $("<option>").val(this.fabricName).text(this.fabricName).appendTo(fabricSelector)
  });
}

function loadAclsForFabric(input){
  console.log("[loadAclsForFabric] Loading ACLs for Fabric: "+input)
  resp = aclmApiWrapper("post","/fabric/selectFabric", {'fabricName':input, 'updateCache': true }, consoleLog)
}


function aclmApiWrapper(method, path, payload, success){
  console.log("[aclmApiWrapper] API Call Submitted: Method:"+method+" Path:"+path+" Payload:"+JSON.stringify(payload))

  var url = "http://"+ACLM_API+path
  console.log("[aclmApiWrapper] Generated URL: "+url)



  $.ajaxSetup({
    // global: false,
    xhrFields: { withCredentials: true },
    crossDomain: true,
    dataType: "json"
  });

  switch(method) {
    case "get":
    console.log("[aclmApiWrapper] Get");
    var apiCall = $.ajax({
      type: "GET",
      url: url,
      //data: payload,
      success: success
    });
    return apiCall;
    break;
      break;
    case "post":
      console.log("[aclmApiWrapper] Post");
      var apiCall = $.ajax({
        type: "POST",
        url: url,
        data: payload,
        success: success
      });
      return apiCall;
      break;
    case "put":
      // code block
      break;
    default:
      // code block
  }


      // // Get some values from elements on the page:
      // var $form = $( this ),
      //   term = $form.find( "input[name='s']" ).val(),
      //   url = $form.attr( "action" );
      //
      // // Send the data using post
      // var url = "https://" + ACLM_API +
      // var posting = $.post(
      //   url,
      //   { s: term }
      //   )
      //   .done(function() {
      //     alert( "second success" );
      //   })
      //   .fail(function() {
      //     alert( "error" );
      //   })
      //   .always(function() {
      //     alert( "finished" );
      //   });


}

// Setup Ajax Loading
// AJAX Setup
$(document).ajaxStart(function() {
  console.log("[ajaxStart] Start Ajax Call")
  $('#loadingModal').modal('show')
});

$(document).ajaxStop(function() {
  console.log("[ajaxStop] Stop Ajax Call")
  $('#loadingModal').modal('hide')
});

$(document).ready(function(){


  // Update Logon Menu
  updateLogonMenu();

  // Logged On
  if (LOGGED_ON === true){
    console.log("[onReady] Logged On - Loading Fabrics")
    loadFabrics()
    //console.log(resp)
  }

  // Keep open tab on refresh
  $('a[data-toggle="tab"]').on('show.bs.tab', function(e) {
    localStorage.setItem('activeTab', $(e.target).attr('href'));
  });
  var activeTab = localStorage.getItem('activeTab');
  if (activeTab) {
    $('#v-pills-tab a[href="' + activeTab + '"]').tab('show');
  }

  $('#logonForm').submit(function(e){
    console.log("[Logon Form] Form Submit Triggered")
    // Stop form from submitting normally
    e.preventDefault();
    resp = aclmApiWrapper("post","/logon",{"username":"apiuser", "password":"C!sco123"}, loggedOn)
  });

  $('#logoutForm').submit(function(e){
    console.log("[Logout Form] Form Submit Triggered")
    // Stop form from submitting normally
    e.preventDefault();
    resp = aclmApiWrapper("post","/logout", null, loggedOut)
  });



  $('#selectFabricForm').submit(function(e){
    // Stop form from submitting normally
    e.preventDefault();
    console.log("[Select Fabric Form] Form Submit Triggered")
    //console.log($(this).serialize())
    var fabricSelector = $("#selectFabric")
    console.log("[Select Fabric Form] Selected Fabric: "+fabricSelector.val())

    // Load ACLs for Selected Fabric
    loadAclsForFabric(fabricSelector.val())

  });

  $('#selectFabric').change(function(e){
    $('#selectFabricForm').submit();
  });

});
