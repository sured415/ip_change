class flow {
        public :
                uint32_t ip_src;
                uint32_t ip_dst;
		uint16_t sport;
		uint16_t dport;

                flow(){}
                flow(uint32_t ip_src, uint32_t ip_dst, uint16_t sport, uint16_t dport) : ip_src(ip_src), ip_dst(ip_dst), sport(sport), dport(dport) {}

                bool operator < (const flow rh) const {
                        if(this->ip_src < rh.ip_src) return true;
                        if(this->ip_src > rh.ip_src) return false;
                        if(this->ip_dst < rh.ip_dst) return true;
			if(this->ip_dst > rh.ip_dst) return false;
			if(this->sport < rh.sport) return true;
			if(this->sport > rh.sport) return false;
			if(this->dport < rh.dport) return true;
                        return false;
                }

                flow reverse_flow() {
                        return flow(ip_dst, ip_src, dport, sport);
                }
};
