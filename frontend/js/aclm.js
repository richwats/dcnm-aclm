
var ACLM_API = null;
var DCNM_SVC = null;
var LOGGED_ON = false;  // used?
var SELECTED_FABRIC = null;
var SELECTED_ACL = null;
var FABRIC_INVENTORY = null;
var ACL_DETAIL = null;
var OFFLOADED = null;

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

// function autoLogon(){
//   var resttoken = getCookie('resttoken')
//   console.log("[AutoLogon] REST Token: "+JSON.stringify(resttoken))
//   LOGGED_ON = true;
// }

// function initSession(){
//   // Clear & Reset Backend Session
//   console.log("[initSession] Initialise Backend Session")
//   resp = aclmApiWrapper("post","/session", null, null)
// }

function clearSession(){
  // Clear & Reset Backend Session
  console.log("[clearSession] Clear Backend Session")
  resp = aclmApiWrapper("delete","/session", null, null)

  // Clear local storage
  localStorage.clear()

  // Reload Window
  location.reload()

}

function updateLogonMenu(){
  // Check if session cookie present
  var loggedOutMenu = $('.loggedOutMenu');
  var loggedOnMenu =$('.loggedOnMenu');
  var sessionCookie = getCookie('dcnm_aclm');
  console.log("[updateLogonMenu] Session: "+JSON.stringify(sessionCookie))

  if (OFFLOADED == false){
    // Standalone - Need Logon/Logoff
    if (sessionCookie != null) {
      // Logged On
      loggedOnMenu.removeClass('d-none');
      loggedOutMenu.addClass('d-none');

      //fabricAclDisplay
      $('#fabricAclDisplay').removeClass("d-none")

      LOGGED_ON = true;

    }
    else {
      // Logged Off
      loggedOnMenu.addClass('d-none');
      loggedOutMenu.removeClass('d-none');

      //fabricAclDisplay
      $('#fabricAclDisplay').addClass("d-none")

      LOGGED_ON = false;
    }
  }
  else {
    // Offloaded - Don't show Logout Button - Assume Logged On
    loggedOnMenu.removeClass('d-none');
    loggedOutMenu.addClass('d-none');
    $('#fabricAclDisplay').removeClass("d-none")
    $("#logoutForm").addClass('d-none').attr("disabled","disabled")
    $("#logonForm").attr("disabled","disabled")
    LOGGED_ON = true
  }


}

function loggedOn(input){
  // Logged On Successfully
  console.log("[loggedOn] "+JSON.stringify(input))

  // Update Menu
  updateLogonMenu();

  // Load Fabrics
  loadFabrics();

  // // Trigger Fabric Load
  // $('#selectFabricForm').submit();
}

function loggedOut(input){
  // Logged On Successfully
  console.log("[loggedOut] "+JSON.stringify(input))
  updateLogonMenu();

  // Clear local storage
  localStorage.clear()

}

function consoleLog(input){
  console.log("[consoleLogger] "+JSON.stringify(input))
}

function deployPolicies(){
  console.log("[deployPolicies] Policies to deploy: "+JSON.stringify(ACL_DETAIL.toDeploy))



  resp = aclmApiWrapper("post","/aclm/"+ACL_DETAIL.hash+"/deploy", null, updatePolicyStatus)
}

function updatePolicyStatus(apiResponse){
  console.log("[updatePolicyStatus] API Response: "+JSON.stringify(apiResponse))
  // Clear Policy Table
  var policyTable = $("#policyStatusTable")
  policyTable.find("tbody").empty()

  $.each(apiResponse.deployOutput, function(serialNumber, entry){
    var row = $("<tr>").appendTo(policyTable)
    $("<td>").text(serialNumber).appendTo(row)
    $("<td>").text(entry.status).appendTo(row)
  })

  // Open selectedDevices Modal
  $("#policyStatusModal").modal('show')

  // Update Selected ACL
  SELECTED_ACL = apiResponse.hash
  localStorage.setItem('SELECTED_ACL', SELECTED_ACL)

  // Refresh Fabric
  $('#selectFabricForm').submit();
}

function refreshFabric(apiResponse){
  console.log("[refreshFabric] Refresh Fabric: "+SELECTED_FABRIC)

  // Update Selected ACL
  SELECTED_ACL = apiResponse.hash
  localStorage.setItem('SELECTED_ACL', SELECTED_ACL)

  $('#selectFabricForm').submit();

  // if (apiResponse != ""){
  //   console.log("[refreshFabric] API Reponse: "+JSON.stringify(apiResponse))
  //
  //   SELECTED_ACL = apiResponse.hash
  //   localStorage.setItem('SELECTED_ACL', SELECTED_ACL)
  //
  //   $('#selectFabricForm').submit();
  //
  //   // Update Policy Status
  //   updatePolicyStatus(apiResponse)
  //
  //
  // }
  // else {
  //   $('#selectFabricForm').submit();
  // }

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

  // Check localStorage
  if (localStorage.getItem('SELECTED_FABRIC')){
    SELECTED_FABRIC = localStorage.getItem('SELECTED_FABRIC')
    fabricSelector.val(SELECTED_FABRIC)
    fabricSelector.trigger('change')
  }
  else {
    // Select 1st Fabric
    first = fabricSelector.children().first().val()
    fabricSelector.val(first)
    fabricSelector.trigger('change')
  }

}

function loadAclsForFabric(input){
  console.log("[loadAclsForFabric] Loading ACLs for Fabric: "+input)

  // Set SELECTED_FABRIC
  SELECTED_FABRIC = input

  // Set localStorage
  localStorage.setItem('SELECTED_FABRIC',SELECTED_FABRIC)

  resp = aclmApiWrapper("get","/fabric/selectFabric/"+input+"?updateCache=true", null , buildAclList)

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

  // Delete Button
  $("#deleteAclEntryButton")
  .removeAttr('disabled')
  .data('title','Delete ACL Entry')
  .data('message','Please confirm you want to delete ACL entry #'+position)
  .data('confirm','deleteAclEntry')
  .val(position)
  // .attr('data-callback','test')

  // Triger
  $("#aclType").trigger("change")

  // Show modal
  $("#aclEntryModal").modal("show")
}

function deleteAcl(hash){
  console.log("[deleteAcl] Delete ACL Hash: "+hash)

  // console.log("[deleteAclEntry] DELETE payload: "+JSON.stringify(payload))
  resp = aclmApiWrapper("delete","/aclm/"+hash, null, refreshFabric)

  if (resp){
    $('#aclEntryModal').modal('hide')
  }

  // Clear Selected ACL
  SELECTED_ACL = null
  localStorage.removeItem('SELECTED_ACL')

  // Hide aclTable
  $('#aclTableDisplay').addClass('d-none')

}

function deleteAclEntry(position){
  console.log("[deleteAclEntry] Delete ACL Entry: "+position)

  // Remove Entry
  var payload = ACL_DETAIL
  delete payload.acl.entries[position]
  console.log("[deleteAclEntry] PUT payload: "+JSON.stringify(payload))
  resp = aclmApiWrapper("put","/aclm/"+payload.hash+"?update=json", payload, refreshFabric)

  if (resp){
    $('#aclEntryModal').modal('hide')
  }

  // Reset Disabled
  $("#deleteAclEntryButton").attr('disabled','disabled').removeAttr('data-position').removeAttr('value')

}

function loadAclDetails(input){
  console.log("[loadAclDetails] Loading ACL Details for Hash: "+input)
  resp = aclmApiWrapper("get","/aclm/"+input, null, buildAclDetails)
}

function buildAclDetails(input){
  console.log("[buildAclDetails] ACL: "+JSON.stringify(input))
  // console.log("[buildAclDetails] Building ACL Details for Hash: "+input)

  // Set localStorage
  SELECTED_ACL = input.hash
  localStorage.setItem('SELECTED_ACL', SELECTED_ACL)
  // console.log(localStorage)

  ACL_DETAIL = input

  // Check & Display Warning
  if (ACL_DETAIL.status == "NotApplied"){
    $('#aclTableWarning').removeClass('d-none').html("<i><b>WARNING:</b></i> This ACL is not currently applied to any switch and will be lost should the ACL Manager session expire")
  }
  else {
    $('#aclTableWarning').addClass('d-none').html()
  }

  // Check toDeploy
  if (ACL_DETAIL.toDeploy.length > 0){
    console.log("[buildAclDetails] Polices to deploy: "+JSON.stringify(ACL_DETAIL.toDeploy))
    $("#deployPoliciesButton").removeClass("disabled").removeClass("btn-primary").addClass("btn-warning").removeAttr("disabled")
  }
  else {
    $("#deployPoliciesButton").addClass("disabled").addClass("btn-primary").removeClass("btn-warning").attr("disabled","disabled")
  }

  // // Set Active List Member
  // $("#acl-listgroup .active").removeClass("active")
  // $("#acl-"+input.hash).addClass("active")

  // Set ACL Name
  $('#aclNameSpan').text(input.name)

  // Set deleteAclButton
  $('#deleteAclButton')
  .val(input.hash)
  .data('title','Delete ACL '+input.name)
  .data('message','Please confirm you want to delete ACL '+input.name+'<br><br><i><b>WARNING:</b></i> This will automatically remove policies from assigned switches')

  // Build Edit ACL Name Modal
  var editAclName = $('#editAclName')
  editAclName.val(input.name)

  // Build Edit CLI Modal
  var aclCliContent = $('#aclCliContent')
  aclCliContent.val(input.cli)

  // Build Selected Devices Modal
  var selectedDevicesTable = $("#selectedDevicesTable").DataTable()
  selectedDevicesTable.clear()

  $.each(FABRIC_INVENTORY, function( serialNumber, entry){
    // Determine poliycId
      if (ACL_DETAIL.policies[serialNumber]) {
        var policyId = ACL_DETAIL.policies[serialNumber]

        // Checkbox HTML - Checked
        var checkboxHtml = '<div class="form-group form-check mt-1"><input id="cb-'+entry.serialNumber+'" type="checkbox" checked="checked" class="form-check-input" data-policyid="'+policyId+'" name="selectedDevice" value="'+entry.serialNumber+'"></div>'
      }
      else {
        var policyId = null
        // Checkbox HTML - Not Checked
        var checkboxHtml = '<div class="form-group form-check mt-1"><input id="cb-'+entry.serialNumber+'" type="checkbox" class="form-check-input" data-policyid="'+policyId+'" name="selectedDevice" value="'+entry.serialNumber+'"></div>'
      }

    var data = {
      checkboxInput: checkboxHtml,
      fabricName: entry.fabricName,
      displayName: entry.displayName,
      model: entry.model,
      serialNumber: entry.serialNumber,
      switchRole: entry.switchRole,
      release: entry.release,
      policyId: policyId
    }
    var newRow = selectedDevicesTable.row.add(data).draw().node()
  })



  // selectedDevicesTable.find("tbody").empty()
  // $.each(FABRIC_INVENTORY, function( serialNumber, entry){
  //   // Determine poliycId
  //   if (ACL_DETAIL.policies[serialNumber]) {
  //     policyId = ACL_DETAIL.policies[serialNumber]
  //   }
  //   else {
  //     policyId = null
  //   }
  //
  //   // Build Table Row
  //   var newRow = $("<tr>").appendTo(selectedDevicesTable).attr("data-serial", serialNumber)
  //
  //   if (policyId != null){
  //     $("<td>").html('<div class="form-group form-check mt-1"><input id="cb-'+serialNumber+'" type="checkbox" class="form-check-input" data-policyid="'+policyId+'" name="selectedDevice" value="'+entry.serialNumber+'"></div>').appendTo(newRow)
  //     $("#cb-"+serialNumber).attr('checked','checked')
  //   }
  //   else {
  //     $("<td>").html('<div class="form-group form-check mt-1"><input type="checkbox" class="form-check-input" name="selectedDevice" value="'+entry.serialNumber+'"></div>').appendTo(newRow)
  //   }
  //
  //   $("<td>").text(entry.fabricName).appendTo(newRow)
  //   $("<td>").text(entry.displayName).appendTo(newRow)
  //   $("<td>").text(entry.model).appendTo(newRow)
  //   $("<td>").text(entry.serialNumber).appendTo(newRow)
  //   $("<td>").text(entry.switchRole).appendTo(newRow)
  //   $("<td>").text(entry.release).appendTo(newRow)
  //   $("<td>").text(policyId).appendTo(newRow)
  //   $("<td>").text('n/a').appendTo(newRow)
  //
  // })


  // // Copy Template
  // var tabTemplate = $("#tabTemplate")
  // tabPane.html(tabTemplate.html())


  // $('#aclTable').DataTable().draw()

  var dataTable = $("#aclTable").DataTable()
  dataTable.clear()
  $.each(input.acl.entries, function( position, entry){
    console.log("[buildAclDetails] "+position+": "+JSON.stringify(entry))

    buttonHtml = '<button type="button" onclick="buildEditAclModal('+position+')" class="btn btn-sm btn-primary mx-1" name="button"><i data-feather="edit-3"></i></button>'

    var data = {
      button: buttonHtml,
      position: position,
      aclType: entry.aclType,
      remarks: entry.remarks,
      aclProtocol: entry.aclProtocol,
      sourceIpMask: entry.sourceIpMask,
      sourceOperator: entry.sourceOperator,
      sourcePortStart: entry.sourcePortStart,
      sourcePortStop: entry.sourcePortStop,
      destIpMask: entry.destIpMask,
      destOperator: entry.destOperator,
      destPortStart: entry.destPortStart,
      destPortStop: entry.destPortStop,
      extra: entry.extra
    }
    var newRow = dataTable.row.add(data).draw().node()
    $(newRow).attr("data-position", position)

    if (entry.aclType == "remark"){
      $(newRow).addClass('table-info')
    }
    else if (entry.aclType == "permit") {
      $(newRow).addClass('table-success')
    }
    else if (entry.aclType == "deny") {
      $(newRow).addClass('table-danger')
    }

  })

  // // Build Table
  // var aclTable = $("#aclTable")
  // aclTable.find("tbody").empty()
  // $.each(input.acl.entries, function( position, entry){
  //   console.log("[buildAclDetails] "+position+": "+JSON.stringify(entry))
  //   // Build Table Row
  //   var newRow = $("<tr>").appendTo(aclTable).attr("data-position", position)
  //
  //   $("<td>").html('<button type="button" onclick="buildEditAclModal('+position+')" class="btn btn-sm btn-primary mx-1" name="button"><i data-feather="edit-3"></i></button>').appendTo(newRow)
  //   $("<td>").text(position).appendTo(newRow)
  //   $("<td>").text(entry.aclType).appendTo(newRow)
  //
  //   if (entry.aclType == "remark"){
  //     $("<td>").attr("colspan",10).text(entry.remarks).appendTo(newRow)
  //   }
  //   else {
  //     if (entry.aclProtocol == "ip"){
  //       $("<td>").text(entry.aclProtocol).appendTo(newRow)
  //       $("<td>").attr("colspan",4).text(entry.sourceIpMask).appendTo(newRow)
  //       $("<td>").attr("colspan",4).text(entry.destIpMask).appendTo(newRow)
  //       $("<td>").text(entry.extra).appendTo(newRow)
  //     }
  //     else {
  //       $("<td>").text(entry.aclProtocol).appendTo(newRow)
  //       $("<td>").text(entry.sourceIpMask).appendTo(newRow)
  //       $("<td>").text(entry.sourceOperator).appendTo(newRow)
  //       if (entry.sourceOperator == "range"){
  //         $("<td>").text(entry.sourcePortStart).appendTo(newRow)
  //         $("<td>").text(entry.sourcePortStop).appendTo(newRow)
  //       }
  //       else {
  //         $("<td>").attr("colspan",2).text(entry.sourcePortStart).appendTo(newRow)
  //       }
  //       $("<td>").text(entry.destIpMask).appendTo(newRow)
  //       $("<td>").text(entry.destOperator).appendTo(newRow)
  //       if (entry.destOperator == "range"){
  //         $("<td>").text(entry.destPortStart).appendTo(newRow)
  //         $("<td>").text(entry.destPortStop).appendTo(newRow)
  //       }
  //       else {
  //         $("<td>").attr("colspan",2).text(entry.destPortStart).appendTo(newRow)
  //       }
  //       $("<td>").text(entry.extra).appendTo(newRow)
  //     }
  //
  //   }
  //
  // })

  // Bind Functions


  // ACL Entry Modal Scripts
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

  // Unhide
  $('#aclTableDisplay').removeClass("d-none")

}

function buildAclList(input){
  console.log("[buildAclList] Building ACL List")
  // console.log("[buildAclList] ACL: "+JSON.stringify(input))

  var selectAcl = $('#selectAcl')
  selectAcl.empty()

  // var aclList = $("#acl-listgroup")
  // aclList.empty()

  FABRIC_INVENTORY = input.inventory
  console.log("[buildAclList] FABRIC_INVENTORY: "+JSON.stringify(FABRIC_INVENTORY))

  var acls = input.acls
  var displayList = false

  $.each(acls, function (hash, item) {
    // console.log("[buildAclList] ACL Hash: "+hash)
    console.log("[buildAclList] ACL Details: "+JSON.stringify(item))
    displayList = true

    var newOption = $("<option>")
    .text(item.name)
    .val(hash)
    .appendTo(selectAcl)

    // var newListEntry = $("<button>")
    // .addClass("list-group-item")
    // .addClass("list-group-item-action")
    // .addClass("list-group-item-secondary")
    // .val(hash)
    // .attr('id','acl-'+hash)
    // .on("click",function(){
    //   console.log("[Select ACL] ACL: "+hash)
    //   loadAclDetails(hash)
    // })
    // .text(item.name)
    // .appendTo(aclList)

  });

  if (displayList == true){
    console.log("[buildAclList] ACLs Present - Displaying List")
    $("#selectAclForm").removeClass("d-none")
  }
  else {
    console.log("[buildAclList] No ACLs Present")
    $("#selectAclForm").addClass("d-none")
    $('#aclTableDisplay').addClass('d-none')
  }

  // Set Active ACL from localStorage
  // console.log(localStorage)
  if (localStorage.getItem('SELECTED_ACL') != undefined ){
    SELECTED_ACL = localStorage.getItem('SELECTED_ACL')
    console.log("[buildAclList] SELECTED_ACL from localStorage:"+SELECTED_ACL)
    // $('#acl-'+SELECTED_ACL).addClass('active').trigger('click')
    $("#selectAcl").val(SELECTED_ACL).trigger('change')
  }
  else if (displayList == true) {
    // Options exist but not previously selected - use first
    $("#selectAcl").trigger('change')

  }
  else {
    // Hide ACL Table
    console.log("[buildAclList] No SELECTED_ACL from localStorage. Hiding Table")
    $('#aclTableDisplay').addClass('d-none')
  }

  // Icons
  feather.replace()

}

function aclmApiWrapper(method, path, payload, success){
  console.log("[aclmApiWrapper] API Call Submitted: Method:"+method+" Path:"+path+" Payload:"+JSON.stringify(payload))

  // var url = "http://"+ACLM_API+path
  var url = ACLM_API+path
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

      break;
    case "delete":
      // console.log("[aclmApiWrapper] Delete");
      var apiCall = $.ajax({
        type: "DELETE",
        url: url,
        //data: payload,
        success: success
      });
      break;
    case "post":
      // console.log("[aclmApiWrapper] Post");
      var apiCall = $.ajax({
        type: "POST",
        url: url,
        data: JSON.stringify(payload),
        success: success
      });
      break;
    case "put":
      // console.log("[aclmApiWrapper] Put");
      var apiCall = $.ajax({
        type: "PUT",
        url: url,
        data: JSON.stringify(payload),
        success: success
      });
      break;
    default:
      break;
      // code block
  }
  console.log("[aclmApiWrapper] Response: "+JSON.stringify(apiCall))
  return apiCall;

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

  // Lookup Backend Service

  // {
  //   "ServiceName": "string",
  //   "FabricId": "string",
  //   "ImageTag": "string",
  //   "IPAddress": "string",
  //   "Port": 0,
  //   "PublicIP": "string",
  //   "PublishedPort": 0,
  //   "Protocol": "string"
  // }


  // DCNM_SVC = AfwDiscoverService("dcnm_aclm-0.1");
  //   if (DCNM_SVC.length == 0) {
  //     console.log("[onReady] Failure Discover ACLM Service ");
  //     ACLM_API = "/appcenter/Cisco/DCNM_ACLM/aclm_api"
  //     // return null;
  //   }
  //   else {
  //     console.log("[onReady] Discovered Service: "+JSON.stringify(DCNM_SVC))
  //     ACLM_API = DCNM_SVC.IPAddress + ":" + DCNM_SVC.Port
  //   }


  // Setup Select2
  $(".enableSelect2").select2(); // theme: 'bootstrap4',  { containerCssClass: 'all', theme: 'bootstrap4' }

  console.log("[onReady] Location: "+$(location).attr('host'))
  if ($(location).attr('hostname') != "localhost"){
    // Assume DCNM Offload Reverse Proxy
    ACLM_API = "/appcenter/Cisco/DCNM_ACLM/aclm_api"
    OFFLOADED = true
  }
  else {
    // Assume local backend container
    ACLM_API = "http://localhost:5000"
    OFFLOADED = false
  }

  // // Auto Logon for 'resttoken'
  // autoLogon();

  // Update Logon Menu
  updateLogonMenu();

  // Logged On
  if (LOGGED_ON === true){
    console.log("[onReady] Logged On - Loading Fabrics")
    loadFabrics()
    //console.log(resp)
  }

  // Setup DataTables
  $('#aclTable').DataTable({
    order: [[ 1, "asc" ]],
    stateSave: true,
    rowId: function(entry){return "acl-"+entry.position},
    drawCallback: function(settings){
      feather.replace()
    },
    columns: [
      { data: "button", orderable: false },
      { data: "position" },
      { data: "aclType" },
      { data: "remarks" },
      { data: "aclProtocol" },
      { data: "sourceIpMask" },
      { data: "sourceOperator" },
      { data: "sourcePortStart" },
      { data: "sourcePortStop" },
      { data: "destIpMask" },
      { data: "destOperator" },
      { data: "destPortStart" },
      { data: "destPortStop" },
      { data: "extra" }
    ]
  });

  $('#selectedDevicesTable').DataTable({
    stateSave: true,
    rowId: function(entry){return "sn-"+entry.serialNumber},
    columns: [
      { data: "checkboxInput", orderable: false },
      { data: "fabricName" },
      { data: "displayName" },
      { data: "model" },
      { data: "serialNumber" },
      { data: "switchRole" },
      { data: "release" },
      { data: "policyId" }
    ]
  })

  // // Keep open tab on refresh
  // $('a[data-toggle="tab"]').on('show.bs.tab', function(e) {
  //   localStorage.setItem('activeTab', $(e.target).attr('href'));
  // });
  // var activeTab = localStorage.getItem('activeTab');
  // if (activeTab) {
  //   $('#v-pills-tab a[href="' + activeTab + '"]').tab('show');
  // }

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

    // Hide ACL Table
    $('#aclTableDisplay').addClass('d-none')

    // Load ACLs for Selected Fabric
    loadAclsForFabric(fabricSelector.val())

  });

  $('#selectFabric').change(function(e){
    $('#selectFabricForm').submit();
  });

  // Create New ACL  Form
  $('#createNewAclForm').submit(function(e){
    // Stop form from submitting normally
    e.preventDefault();
    console.log("[Create New ACL Form] Form Submit Triggered")
    var newAclName = $("#newAclName").val()
    var importedAclContent = $("#importedAclContent").val()

    if (newAclName != null){
      // Use Name
      console.log("[Create New ACL Form] Name Changed. New Name: "+newAclName)

      payload = {
        'name': newAclName,
        'acl': {'name': newAclName }
       }
      console.log("[Create New ACL Form] POST payload: "+JSON.stringify(payload))

      resp = aclmApiWrapper("post","/aclm/", payload, refreshFabric)

      if (resp){
        $('#createNewAclModal').modal('hide')
      }
    }
  });

  // Select ACL
  $('#selectAcl').change(function(e){
    console.log("[Select ACL] ACL: "+$(this).val())
    loadAclDetails($(this).val())
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
    }
    else {
      console.log("[Edit CLI Form] CLI Unchanged. Force Refresh of CLI")
    }

    var payload = ACL_DETAIL
    payload.cli = aclCliContent
    console.log("[Edit CLI Form] PUT payload: "+JSON.stringify(payload))
    resp = aclmApiWrapper("put","/aclm/"+payload.hash+"?update=cli", payload, refreshFabric)

    if (resp){
      $('#editCliModal').modal('hide')
    }

  });

  // Select Devices Form
  $('#selectedDevicesForm').submit(function(e){
    // Stop form from submitting normally
    e.preventDefault();
    console.log("[Edit Selected Devices Form] Form Submit Triggered")
    var checkedBoxInputs = $("#selectedDevicesForm :checkbox")

    var toAttach = []
    var toDetach = []

    $.each(checkedBoxInputs, function(){
      if ($(this).prop('checked') === true){
        // Switch Selected
        if ($(this).data('policyid') != undefined){
          // Existing Policy - No Change
        }
        else {
          // Add to Attach
          console.log("[Edit Selected Devices Form] Attach Switch: "+$(this).val())
          toAttach.push($(this).val())
        }
      }
      else {
        // Switch Not Selected
        if ($(this).data('policyid') != undefined){
          console.log("[Edit Selected Devices Form] Detach Switch: "+$(this).val())
          toDetach.push($(this).val())
        }
        else {
          // No Existing Policy - No Change
        }
      }
    })
    console.log("[Edit Selected Devices Form] toAttach List: "+JSON.stringify(toAttach))
    console.log("[Edit Selected Devices Form] toDetach List: "+JSON.stringify(toDetach))

    var payload = ACL_DETAIL
    payload.toAttach = toAttach
    payload.toDetach = toDetach

    console.log("[Edit ACL Entry] PUT payload: "+JSON.stringify(payload))
    resp = aclmApiWrapper("put","/aclm/"+payload.hash+"?update=json", payload, refreshFabric)

    if (resp){
      $('#selectedDevicesModal').modal('hide')
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
    // console.log($('#aclEntryForm :input[disabled]'))

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

  // New ACL Modal Setup
  $("#newAclName").change(function( event ) {
    if ($(event.target)[0].value != "") {
      console.log("[Create New ACL Modal] Disabling Import by CLI")
      $("#importedAclContent").attr("Disabled","True")
    }
    else {
      console.log("[Create New ACL Modal] Enabling Import by CLI")
      $("#importedAclContent").removeAttr("Disabled")
    }
  });
  $("#importedAclContent").change(function( event ) {
    if ($(event.target)[0].value != "") {
      console.log("[Create New ACL Modal] Disabling Create by Name")
      $("#newAclName").attr("Disabled","True")
    }
    else {
      console.log("[Create New ACL Modal] Enabling Create by name")
      $("#newAclName").removeAttr("Disabled")
    }
  });

  // Confirmation Modal Setup
  $("#confirmModal").on("show.bs.modal", function (event) {
    // Button that triggered the modal
    var button = $(event.relatedTarget)
    var value = button.val() // Extract info from data-* attributes
    var confirm = eval(button.data("confirm"))

    var title = button.data("title")
    var message = button.data("message")
    // If necessary, you could initiate an AJAX request here (and then do the updating in a callback).
    // Update the modal's content. We'll use jQuery here, but you could use a data binding library or other methods instead.
    var modal = $(this)
    modal.find('.modal-title').text(title)
    modal.find('.modal-body .alert').html(message)
    // Reset All Click Functions
    var test = modal.find('.modal-footer .confirmButton').off("click")
    // console.log(test)
    // Find New Click Function
    modal.find('.modal-footer .confirmButton').on("click",function(){
      // Console Log
      console.log("[confirmModal] Executing Callback: "+button.data("confirm")+" Value: "+value)

      // Close All Modals
      $(".modal").modal('hide')

      // Excecute Callback
      confirm(value)



    })
  })


});
