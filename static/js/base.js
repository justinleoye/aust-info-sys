$(document).ready(function(){
    //为输入添加更多输入框
    var add_item_func = function(){
        if($(this).attr("data") !=null){
            var input_item = $($(this).attr("data"));
        }else {
        var input_item = $(this).prev().clone();
        }
        //input_item.val("");
        $(this).before(input_item);
    };
    $(document).delegate('.add-input-item','click',add_item_func);

    // 删除添加后的输入框
    var remove_item_func = function(){
        var input_item = $(this).prev();
        $(this).remove();
        input_item.remove();
        
    };
    $(document).delegate('.remove-input-item','click',remove_item_func);
    
});
