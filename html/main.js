function htmlEncode(s)
{
    var ret = $('<div/>').text(s).html();
    // make links clickable!
    return ret;
}

function deleteEvent(id)
{
    $.post("deleteEvent", id.toString());
}

$(document).ready(function() {

    if(Cookies.get('name') != undefined) {
        $("#name").val(Cookies.get('name'));
    }
    
    $("#name").keyup(function(event){
        Cookies.set('name', $('#name').val());
    });

    
    $("#msg").keyup(function(event){
      if(event.keyCode == 13) {
          var obj={};
          obj.msg = $("#msg").val();
          obj.channel=2;
          obj.originator = $('#name').val();
          if (obj.msg.length > 0)
              $.post("sendEvent", JSON.stringify(obj));
          $("#msg").val("");
      }  
    });

    var lastLog = 0;
    var updateLog;
    updateLog = function(data)
    {
        $("#viewers").text(data.numclients);
	var lastLog = data.last*1;
	var s1 = "";
        var s2 = "";
        if(data.restart == true) {
            $("#logs").html("");
            $("#logs2").html("");
        }
	for(var x in data.msgs)
	{
            if(data.msgs[x].channel==1)
	        s1 = htmlEncode(data.msgs[x].message) + "<hr/>" + s1;
            else if(data.msgs[x].channel==2)
                s2 = htmlEncode(data.msgs[x].originator) + ' <a href="javascript:deleteEvent('+data.msgs[x].id+')">x</a> <br/>'+htmlEncode(data.msgs[x].message) + "<hr/>" + s2;
	}
	$("#logs").html(s1+$("#logs").html());
        $("#logs2").html(s2+$("#logs2").html());

	var failFunction;
	failFunction = function(){
            console.log("We had a failure");
            var fail2Function = function() { $.getJSON("newEvents?since="+lastLog, updateLog).fail(failFunction);}
            window.setTimeout(fail2Function, 1000);

	};
	$.getJSON("newEvents?since="+lastLog, updateLog).fail(failFunction);
    }
    $.getJSON("allEvents", updateLog);
});
