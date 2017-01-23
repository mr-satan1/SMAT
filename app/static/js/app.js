$(function() {
    $('#submit').click(function() {
        event.preventDefault();
        var form_data = new FormData($('#uploadform')[0]);
        $.ajax({
            type: 'POST',
            url: '/uploadajax',
            data: form_data,
            contentType: false,
            processData: false,
            dataType: 'json'
        }).done(function(data, textStatus, jqXHR){
            console.log(data);
            console.log(textStatus);
            console.log(jqXHR);
            console.log('Success!');
            $("#resultFilename").text(data['name']);
            $("#resultFilesize").text(data['size']);
            $("#resultTest").text(data['test']);
            $("#resultVT").text(data['vt']);
            $("#resultMD5").text(data['md5'])
        }).fail(function(data){
            alert('error!');
        });
    });
}); 