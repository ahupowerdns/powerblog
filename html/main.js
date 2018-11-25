// for shame
function htmlEncode(s)
{
    return $('<div/>').text(s).html(); 
}

$(document).ready(function(){
    $("#msg").keyup(function(event){
      if(event.keyCode == 13) {
          var obj={};
          obj.msg = $("#msg").val();
          obj.channel=1;
          if (obj.msg.length > 0)
              $.post("sendEvent", JSON.stringify(obj));
          $("#msg").val("");
      }  
    });

    $("#msg2").keyup(function(event){
      if(event.keyCode == 13) {
          var obj={};
          obj.msg = $("#msg2").val();
          obj.channel=2;
          if (obj.msg.length > 0)
              $.post("sendEvent", JSON.stringify(obj));
          $("#msg2").val("");
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
	for(var x in data.msgs)
	{
            if(data.msgs[x].channel==1)
	        s1 = htmlEncode(data.msgs[x].message) + "<hr/>" + s1;
            else if(data.msgs[x].channel==2)
                s2 = htmlEncode(data.msgs[x].message) + "<hr/>" + s2;
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
