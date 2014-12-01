$(document).ready(function(){
    $('button[type=submit]').click(function(){
        var family_info = [];
        var family_info_items = $('.family_info').find('.family_info_item');
        console.log('family_info_items:',family_info_items);

        for(var i=0;i<family_info_items.length;i++){
            var inputs = $(family_info_items[i]).find('input');
            console.log('inputs:',inputs);
            if($(inputs[0]).val()!=''||$(inputs[1]).val()!=''||$(inputs[2]).val()!=''||$(inputs[3]).val()!='')
                family_info.push({
                    name: $(inputs[0]).val(),
                    relationship: $(inputs[1]).val(),
                    work_place: $(inputs[2]).val(),
                    contact: $(inputs[3]).val()
                });
        }
        console.log('family_info:',family_info);
        $('input[name=family_info]').val(JSON.stringify(family_info));
        //return false;
    });
});
