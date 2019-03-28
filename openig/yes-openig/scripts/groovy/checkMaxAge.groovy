return next.handle(context, request)

.thenOnResult({ response ->
 
if (response.status.getCode()==320 && response.headers['Location']!=null) {
	reader = response.headers['Location'].getFirstValue()
	if (reader.contains(error)){
		reader = reader.replace(error,description)
		reader = reader.replace("invalid_request",error)
		response.headers.put("Location",reader)
		
	}
}
else if (response.status.getCode()==400){
	reader = response.entity.getJson()
	if (reader.error_description==error){
		reader.error=error
		reader.error_description=description
		response.entity.setJson(reader)
	}
}
})