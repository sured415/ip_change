struct flow {
        public :
                uint32_t ip_src;
                uint32_t ip_dst;

                flow(){}
                
                bool operator < (const flow& rh) const {
                        if(this->ip_src < rh.ip_src) return true;
                        if(this->ip_src > rh.ip_src) return false;
                        if(this->ip_dst < rh.ip_dst) return true;
                        return false;
                }

                flow reverse_flow() {
			uint32_t dump;
			dump = this->ip_src;
			this->ip_src = this->ip_dst;
                        this->ip_dst = dump;
                }
};
