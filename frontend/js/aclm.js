
var ACLM_API = "localhost:32768";

var LOGGED_ON = false;

var SELECTED_FABRIC = null;
var FABRIC_INVENTORY = null;
var ACL_DETAIL = null;

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

function refreshFabric(){
  console.log("[refreshFabric] Refresh Fabric")
  $('#selectFabricForm').submit();
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
  SELECTED_FABRIC = input
  resp = aclmApiWrapper("post","/fabric/selectFabric", {'fabricName':input, 'updateCache': true }, buildAclList)

  // console.log("[loadAclsForFabric] Loading Inventory for Fabric: "+input)
  // resp = aclmApiWrapper("post","/fabric/selectFabric", {'fabricName':input, 'updateCache': true }, buildAclList)
}


function buildNewAclModal(position){
  // Load ACL values into modal form
  console.log("[buildNewAclModal] Clearing Modal")
  $("#aclEntryForm").trigger("reset")

  // Triger
  $("#aclType").trigger("change")

  // Show modal
  $("#aclEntryModal").modal("show")
}

function buildEditAclModal(position){
  // Load ACL values into modal form
  aclDetails = ACL_DETAIL.acl.entries[position]
  console.log("[buildEditAclModal] ACL: "+JSON.stringify(aclDetails))

  $("#aclPosition").val(position)
  $("#aclType").val(aclDetails['aclType'])
  $("#aclRemarks").val(aclDetails['remarks'])
  $("#aclProtocol").val(aclDetails['aclProtocol'])
  $("#aclSourceIpMask").val(aclDetails['sourceIpMask'])
  $("#aclSourceOperator").val(aclDetails['sourceOperator'])
  $("#aclSourcePort").val(aclDetails['sourcePortStart'])
  $("#aclSourcePortStart").val(aclDetails['sourcePortStart'])
  $("#aclSourcePortStop").val(aclDetails['sourcePortStop'])
  $("#aclDestIpMask").val(aclDetails['destIpMask'])
  $("#aclDestOperator").val(aclDetails['destOperator'])
  $("#aclDestPort").val(aclDetails['destPortStart'])
  $("#aclDestPortStart").val(aclDetails['destPortStart'])
  $("#aclDestPortStop").val(aclDetails['destPortStop'])
  $("#aclExtra").val(aclDetails['extra'])

  // Triger
  $("#aclType").trigger("change")

  // Show modal
  $("#aclEntryModal").modal("show")
}

function loadAclDetails(input){
  console.log("[loadAclDetails] Loading ACL Details for Hash: "+input)
  resp = aclmApiWrapper("get","/aclm/"+input, null, buildAclDetails)
}

function buildAclDetails(input){
  console.log("[buildAclDetails] ACL: "+JSON.stringify(input))
  // console.log("[buildAclDetails] Building ACL Details for Hash: "+input)

  ACL_DETAIL = input

  //
  var selector = "#list-"+input.hash
  var tabPane = $(selector)
  // console.log(tabPane)

  // Set ACL Name
  $('#aclNameSpan').text(input.name)

  // Build Edit ACL Name Modal
  var editAclName = $('#editAclName')
  editAclName.val(input.name)

  // Build Edit CLI Modal
  var aclCliContent = $('#aclCliContent')
  aclCliContent.val(input.cli)

  // Build Selected Devices Modal
  var selectedDevicesTable = $("#selectedDevicesTable")
  selectedDevicesTable.find("tbody").empty()
  $.each(FABRIC_INVENTORY, function( serialNumber, entry){
    // Determine poliycId
    if (ACL_DETAIL.policies[serialNumber]) {
      policyId = ACL_DETAIL.policies[serialNumber]
    }
    else {
      policyId = null
    }

    // Build Table Row
    var newRow = $("<tr>").appendTo(selectedDevicesTable).attr("data-serial", serialNumber)
    if (policyId != null){
      $("<td>").html('<div class="form-group form-check mt-1"><input type="checkbox" class="form-check-input" checked name="selectedDevice" value="'+entry.serialNumber+'"></div>').appendTo(newRow)
    }
    else {
      $("<td>").html('<div class="form-group form-check mt-1"><input type="checkbox" class="form-check-input" name="selectedDevice" value="'+entry.serialNumber+'"></div>').appendTo(newRow)
    }

    $("<td>").text(entry.fabricName).appendTo(newRow)
    $("<td>").text(entry.displayName).appendTo(newRow)
    $("<td>").text(entry.model).appendTo(newRow)
    $("<td>").text(entry.serialNumber).appendTo(newRow)
    $("<td>").text(entry.switchRole).appendTo(newRow)
    $("<td>").text(entry.release).appendTo(newRow)
    $("<td>").text(policyId).appendTo(newRow)
  })

  // Copy Template
  var tabTemplate = $("#tabTemplate")
  tabPane.html(tabTemplate.html())

  // Build Table
  var aclTable = $(tabPane).find(".aclTable")
  aclTable.find("tbody").empty()
  $.each(input.acl.entries, function( position, entry){
    console.log("[buildAclDetails] "+position+": "+JSON.stringify(entry))
    // Build Table Row
    var newRow = $("<tr>").appendTo(aclTable).attr("data-position", position)

    $("<td>").html('<button type="button" onclick="buildEditAclModal('+position+')" class="btn btn-sm btn-primary mx-1" name="button"><i data-feather="edit-3"></i></button>').appendTo(newRow)
    $("<td>").text(position).appendTo(newRow)
    $("<td>").text(entry.aclType).appendTo(newRow)

    if (entry.aclType == "remark"){
      $("<td>").attr("colspan",10).text(entry.remarks).appendTo(newRow)
    }
    else {
      if (entry.aclProtocol == "ip"){
        $("<td>").text(entry.aclProtocol).appendTo(newRow)
        $("<td>").attr("colspan",4).text(entry.sourceIpMask).appendTo(newRow)
        $("<td>").attr("colspan",4).text(entry.destIpMask).appendTo(newRow)
        $("<td>").text(entry.extra).appendTo(newRow)
      }
      else {
        $("<td>").text(entry.aclProtocol).appendTo(newRow)
        $("<td>").text(entry.sourceIpMask).appendTo(newRow)
        $("<td>").text(entry.sourceOperator).appendTo(newRow)
        if (entry.sourceOperator == "range"){
          $("<td>").text(entry.sourcePortStart).appendTo(newRow)
          $("<td>").text(entry.sourcePortStop).appendTo(newRow)
        }
        else {
          $("<td>").attr("colspan",2).text(entry.sourcePortStart).appendTo(newRow)
        }
        $("<td>").text(entry.destIpMask).appendTo(newRow)
        $("<td>").text(entry.destOperator).appendTo(newRow)
        if (entry.destOperator == "range"){
          $("<td>").text(entry.destPortStart).appendTo(newRow)
          $("<td>").text(entry.destPortStop).appendTo(newRow)
        }
        else {
          $("<td>").attr("colspan",2).text(entry.destPortStart).appendTo(newRow)
        }
        $("<td>").text(entry.extra).appendTo(newRow)
      }

    }

  })

  // Bind Functions

  var aclSourceOperator = $("#aclSourceOperator")
  aclSourceOperator.change(function(e){
    // console.log("TEST: "+$(this).val())

    // Remark
    if ($(this).val() == "range"){
      // Hide/Disable nonRange
      $(".sourcePortRange").removeClass("d-none")
      $(".sourcePortRange").find("input").removeAttr("disabled")
      $(".sourcePort").addClass("d-none")
      $(".sourcePort").find("input").attr("disabled",true)
    }
    else if ($(this).val() != "null") {
      // Hide/Disable range
      $(".sourcePort").removeClass("d-none")
      $(".sourcePort").find("input").removeAttr("disabled")
      $(".sourcePortRange").addClass("d-none")
      $(".sourcePortRange").find("input").attr("disabled",true)
    }
    else {
      // Hide all
      $(".sourcePort").addClass("d-none")
      $(".sourcePort").find("input").attr("disabled",true)
      $(".sourcePortRange").addClass("d-none")
      $(".sourcePortRange").find("input").attr("disabled",true)
    }
  })

  var aclDestOperator = $("#aclDestOperator")
  aclDestOperator.change(function(e){
    // console.log("TEST: "+$(this).val())

    // Remark
    if ($(this).val() == "range"){
      // Hide/Disable nonRange
      $(".destPortRange").removeClass("d-none")
      $(".destPortRange").find("input").removeAttr("disabled")
      $(".destPort").addClass("d-none")
      $(".destPort").find("input").attr("disabled",true)
    }
    else if ($(this).val() != "null") {
      // Hide/Disable range
      $(".destPort").removeClass("d-none")
      $(".destPort").find("input").removeAttr("disabled")
      $(".destPortRange").addClass("d-none")
      $(".destPortRange").find("input").attr("disabled",true)
    }
    else {
      // Hide all
      $(".destPort").addClass("d-none")
      $(".destPort").find("input").attr("disabled",true)
      $(".destPortRange").addClass("d-none")
      $(".destPortRange").find("input").attr("disabled",true)
    }
  })

  var aclProtocol = $("#aclProtocol")
  aclProtocol.change(function(e){
    // console.log("TEST: "+$(this).val())

    // Remark
    if ($(this).val() == "ip"){
      // Hide/Disable nonIpProtocol
      $(".nonIpProtocol").addClass("d-none")
      $(".nonIpProtocol").find("input").attr("disabled",true)
    }
    else {
      $(".nonIpProtocol").removeClass("d-none")
      $(".nonIpProtocol").find("input").removeAttr("disabled")

      // Trigger
      aclSourceOperator.trigger("change")
      aclDestOperator.trigger("change")
    }
  })

  // ACL Entry Modal Scripts
  var aclType = $("#aclType")
  aclType.change(function(e){
    // console.log("TEST: "+$(this).val())

    // Remark
    if ($(this).val() == "remark"){
      // Show remark, hide others
      $(".nonRemark").addClass("d-none")
      $(".nonRemark").find("input").attr("disabled",true)
      $(".aclRemarksGroup").removeClass("d-none")
      $(".aclRemarksGroup").find("input").removeAttr("disabled")
    }
    else {
      // Hide remark, show others
      $(".nonRemark").removeClass("d-none")
      $(".nonRemark").find("input").removeAttr("disabled")
      $(".aclRemarksGroup").addClass("d-none")
      $(".aclRemarksGroup").find("input").attr("disabled",true)

      // Trigger
      aclProtocol.trigger("change")

    }
  })



  // Icons
  feather.replace()

}

function buildAclList(input){
  console.log("[buildAclList] Building ACL List")
  // console.log("[buildAclList] ACL: "+JSON.stringify(input))

  var aclList = $("#acl-list-tab")
  aclList.empty()

  var contentTab = $("#acl-content-tab")
  contentTab.empty()

  // var tabTemplate = $("#tabTemplate")
  // console.log(tabTemplate.html())

  // $(input).each(function(hash, item){
  //   console.log("[buildAclList] ACL Hash: "+hash)
  //   console.log("[buildAclList] ACL Item: "+JSON.stringify(item))
  // })

  FABRIC_INVENTORY = input.inventory
  console.log("[buildAclList] FABRIC_INVENTORY: "+JSON.stringify(FABRIC_INVENTORY))

  var acls = input.acls

  $.each(acls, function (hash, item) {
    // console.log("[buildAclList] ACL Hash: "+hash)
    console.log("[buildAclList] ACL Details: "+JSON.stringify(item))

    var newListEntry = $("<a>")
    .addClass("list-group-item")
    .addClass("list-group-item-action")
    .attr("data-toggle","list")
    .attr("href","#list-"+hash)
    .attr("role","tab")
    .text(item.name)
    .appendTo(aclList)

    var newTab = $("<div>")
    .addClass("tab-pane")
    .attr("id","list-"+hash)
    .attr("role","tabpanel")
    .attr("data-hash",hash)
    // Here on load?
    // .html(tabTemplate.html())
    .appendTo(contentTab)
    .on("show", loadAclDetails(hash))

    // // Set ACL Name
    // $(newTab).find(".navbar-brand").text(item.name)

  });

  // Select 1st Tab
  $('#acl-list-tab a:first-child').tab('show')

  // Icons
  feather.replace()

}

function aclmApiWrapper(method, path, payload, success){
  console.log("[aclmApiWrapper] API Call Submitted: Method:"+method+" Path:"+path+" Payload:"+JSON.stringify(payload))

  var url = "http://"+ACLM_API+path
  console.log("[aclmApiWrapper] Generated URL: "+url)



  $.ajaxSetup({
    // global: false,
    xhrFields: { withCredentials: true },
    crossDomain: true,
    dataType: "json",
    contentType: "application/json; charset=utf-8"
  });

  switch(method) {
    case "get":
    // console.log("[aclmApiWrapper] Get");
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
      // console.log("[aclmApiWrapper] Post");
      var apiCall = $.ajax({
        type: "POST",
        url: url,
        data: JSON.stringify(payload),
        success: success
      });
      return apiCall;
      break;
    case "put":
      // console.log("[aclmApiWrapper] Put");
      var apiCall = $.ajax({
        type: "PUT",
        url: url,
        data: JSON.stringify(payload),
        success: success
      });
      return apiCall;
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
    var username = $("#dcnmUsername").val()
    var password = $("#dcnmPassword").val()
    resp = aclmApiWrapper("post","/logon",{"username": username, "password": password}, loggedOn)
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

  // Edit ACL Name Form
  $('#editAclNameForm').submit(function(e){
    // Stop form from submitting normally
    e.preventDefault();
    console.log("[Edit ACL Name Form] Form Submit Triggered")
    var aclName = $("#editAclName").val()

    if (aclName !== ACL_DETAIL.name){
      // Name Changed
      console.log("[Edit ACL Name Form] Name Changed. New Name: "+aclName)

      var payload = ACL_DETAIL
      payload.name = aclName
      payload.acl.name = aclName

      console.log("[Edit ACL Name Form] PUT payload: "+JSON.stringify(payload))

      resp = aclmApiWrapper("put","/aclm/"+payload.hash, payload, refreshFabric)

      if (resp){
        $('#editAclNameModal').modal('hide')
      }
    }
  });

  // Edit CLI Form
  $('#editAclCliForm').submit(function(e){
    // Stop form from submitting normally
    e.preventDefault();
    console.log("[Edit ACL CLI Form] Form Submit Triggered")
    var aclCliContent = $("#aclCliContent").val()

    if (aclCliContent !== ACL_DETAIL.cli){
      // CLI Changed
      console.log("[Edit CLI Form] CLI Changed. CLI: "+aclCliContent)

      var payload = ACL_DETAIL
      payload.cli = aclCliContent

      console.log("[Edit CLI Form] PUT payload: "+JSON.stringify(payload))

      resp = aclmApiWrapper("put","/aclm/"+payload.hash+"?update=cli", payload, refreshFabric)

      if (resp){
        $('#editCliModal').modal('hide')
      }
    }
  });

  // Edit ACL Entry Form
  $('#aclEntryForm').submit(function(e){
    // Stop form from submitting normally
    e.preventDefault();
    console.log("[Edit ACL Entry Form] Form Submit Triggered")

    var payload = ACL_DETAIL
    var position = $("#aclPosition").val()
    var entry = payload.acl.entries[position]

    if (entry){
      console.log("[Edit ACL Entry Form] Updating Entry: "+position)

    }
    else {
      console.log("[Edit ACL Entry Form] New Entry: "+position)
      var entry = Object()
    }

    // console.log("[Edit ACL Entry Form] Content: "+JSON.stringify($('#aclEntryForm input')))
    console.log($('#aclEntryForm :input[disabled]'))

    entry['aclType'] = $("#aclType").val()
    if (entry['aclType'] == "remark"){
      entry['remarks'] = $("#aclRemarks").val()
    }
    else {
      entry['aclProtocol'] = $("#aclProtocol").val()
      if (entry['aclProtocol'] == "ip"){
        entry['sourceIpMask'] = $("#aclSourceIpMask").val()
        entry['destIpMask'] = $("#aclDestIpMask").val()
      }
      else {
        entry['sourceIpMask'] = $("#aclSourceIpMask").val()
        if ($("#aclSourceOperator").val() == "range"){
          entry['sourceOperator'] = $("#aclSourceOperator").val()
          entry['sourcePortStart'] = $("#aclSourcePortStart").val()
          entry['sourcePortStop'] = $("#aclSourcePortStop").val()
        }
        else if ($("#aclSourceOperator").val() != "null") {
          entry['sourceOperator'] = $("#aclSourceOperator").val()
          entry['sourcePortStart'] = $("#aclSourcePort").val()
        }
        else {
          // No Source Port
        }
        entry['destIpMask'] = $("#aclDestIpMask").val()
        if ($("#aclDestOperator").val() == "range"){
          entry['destOperator'] = $("#aclDestOperator").val()
          entry['destPortStart'] = $("#aclDestPortStart").val()
          entry['destPortStop'] = $("#aclDestPortStop").val()
        }
        else if ($("#aclDestOperator").val() != "null") {
          entry['destOperator'] = $("#aclDestOperator").val()
          entry['destPortStart'] = $("#aclDestPort").val()
        }
        else {
          // No Destination Port
        }
      }
      // Extra
      entry['extra'] = $("#aclExtra").val()
    }
    console.log("[Edit ACL Entry Form] Entry: "+JSON.stringify(entry))

    // Update Entry
    payload.acl.entries[position] = entry
    console.log("[Edit ACL Entry] PUT payload: "+JSON.stringify(payload))
    resp = aclmApiWrapper("put","/aclm/"+payload.hash+"?update=json", payload, refreshFabric)

    if (resp){
      $('#aclEntryModal').modal('hide')
    }

  });




});
