event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("all response",
                SumStats::Key($host = c$id$orig_h),
                SumStats::Observation($num=1));
	if(code == 404){
		SumStats::observe("404 response",
			SumStats::Key($host = c$id$orig_h),
			SumStats::Observation($num=1));
	
		SumStats::observe("unique 404 response",
			SumStats::Key($host = c$id$orig_h),
			SumStats::Observation($str=c$http$uri));
	};
}
event zeek_init(){
     local num_response = SumStats::Reducer(
										$stream="all response",
										$apply=set(SumStats::SUM));
     local num_404_response = SumStats::Reducer(
                                        $stream="404 response",
                                        $apply=set(SumStats::SUM));
     local num_unique_404res = SumStats::Reducer(
                                        $stream="unique 404 response",
                                        $apply=set(SumStats::UNIQUE));
     SumStats::create([$name="dns.requests.unique",
		       $epoch=10min,
		       $reducers=set(num_response, num_404_response, num_unique_404res),
		       $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
			{
				# print (result);
				local unique_404 : double = result["unique 404 response"]$unique/result["404 response"]$sum;
				local ratio_404 : double = result["404 response"]$sum / result["all response"]$sum; 
				if(result["404 response"]$sum > 2 && ratio_404 > 0.2 && unique_404 > 0.5){
					# print (result);
					# print key;
					print fmt("%s is a scanner with %.0f scan attempts on %d urls", key$host, result["404 response"]$sum, result["unique 404 response"]$unique);
				}
			}]);
}

