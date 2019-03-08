#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

#include <unistd.h>
#include <sys/time.h>

template<class T> void dot(const T & t) { std::cout << t << std::flush; }

namespace utils {
  
  template<class T>
  struct Queue
  {
    void push(T const & t)
    {
      {
	std::unique_lock<std::mutex> lk(_mtx);
	_v.push_back(t);
      }
      _cv.notify_one();
    }
    T pop()
    {
      std::unique_lock<std::mutex> lk(_mtx);
      _cv.wait(lk, [this]{ return !_v.empty(); });
      auto t = _v.front();
      _v.pop_front();
      return t;
    }
    bool empty()
    {
      std::unique_lock<std::mutex> lk(_mtx);
      return _v.empty();
    }
  private:
    std::mutex _mtx;
    std::condition_variable _cv;
    std::list<T> _v;
  };
  
} // namespace utils

namespace exchange {
  
  enum {
    TOKEN_BTC = 0,
    TOKEN_USDT,
    TOKEN_MAX,
  };

  enum {
    ORDER_TYPE_DELEGATE_BY_MARKET_PRICE = 0,
    ORDER_TYPE_DELEGATE_BY_LIMIT_PRICE,
    ORDER_TYPE_MAX,
  };

  enum {
    TX_STATUS_INIT = 0,
    TX_STATUS_DONE,
    TX_STATUS_MAX,
  };

  struct Configure
  {
    //static constexpr double initMarketRate = 0.00000005;
    static constexpr double initMarketRate = 0.5;
  };


  struct Order
  {
    Order(int from, int to , int type, double rate, int num, int minNum, std::string user)
      : _from(from), _to(to), _type(type), _rate(rate), _num(num), _minNum(minNum), _user(user)
    {
      _timeStamp = time(NULL);
      _deadline = _timeStamp + 3600;
    }
    int _from;
    int _to;
    int _type;
    double _rate;
    uint64_t _num;
    uint64_t _minNum;
    std::string _user;
    uint32_t _timeStamp;
    uint32_t _deadline;
    
    void dump()
    {
      printf("order-> from:%d, to:%d, type:%d, rate:%.8f, num:%lu, minNum:%lu, user:%s, timeStamp:%u\n"
	     , _from, _to, _type, _rate, _num, _minNum, _user.c_str(), _timeStamp);
    }
  };

  struct comparebynum
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return lhs->_num < rhs->_num;
    }
  };

  struct comparebyrate1
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return lhs->_rate < rhs->_rate;
    }
  };

  struct comparebyrate2
  {
    bool operator()(const std::shared_ptr<Order>& lhs, const std::shared_ptr<Order>& rhs) const
    {
      return !(lhs->_rate < rhs->_rate);
    }
  };
  
  typedef std::shared_ptr<Order> OrderPtr;
  typedef std::multiset<OrderPtr, comparebynum>  OrderNumSet;
  typedef std::multiset<OrderPtr, comparebyrate1> OrderRateSet1;
  typedef std::multiset<OrderPtr, comparebyrate2> OrderRateSet2;
  
  struct Transaction
  {
    Transaction(OrderPtr d1, OrderPtr d2, double rate, uint64_t num)
      : _order1(d1), _order2(d2), _rate(rate), _num(num)
    {
      _timeStamp = time(NULL);
    }
  
    OrderPtr _order1;
    OrderPtr _order2;
    double _rate;
    uint64_t _num;
    uint32_t _timeStamp;
    int _status = 0;
    
    void dump()
    {
      printf("tx-> \n");
      _order1->dump();
      _order2->dump();
      printf("rate:%.8f, num:%lu, timeStamp:%u status:%d\n", _rate, _num, _timeStamp, _status);
    }
  };

  typedef std::shared_ptr<Transaction> TransactionPtr;

  template<class OrderRateSet>
  struct OrderBook
  {
    typedef OrderRateSet OrderRateSet_t;
    
    OrderBook(bool isSeller)
      : _isSeller(isSeller) {}
  
    int insert(OrderPtr order)
    {
      if(order->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE) {
	_marketPriceOrderQueue.push_back(order);
	_marketPriceOrderSetByNum.insert(order);
	return 0;
      }

      if(order->_type == ORDER_TYPE_DELEGATE_BY_LIMIT_PRICE) {
	_limitPriceOrderSetByRate.insert(order);
	if(0 == _limitPriceOrderMapByNum.count(order->_num))
	  _limitPriceOrderMapByNum[order->_num] = std::make_shared<OrderRateSet>();
	_limitPriceOrderMapByNum[order->_num]->insert(order);
	return 0;
      }
      
      return -1;
    }
  
    bool _isSeller;
    
    std::queue<OrderPtr> _marketPriceOrderQueue;
    OrderNumSet _marketPriceOrderSetByNum;

    OrderRateSet _limitPriceOrderSetByRate;
    std::map<uint64_t, std::shared_ptr<OrderRateSet>> _limitPriceOrderMapByNum;
    
  };

  struct MatchEngine
  {
    void run(volatile bool* alive)
    {
      while(*alive) {
	
	while(!_qin->empty()){
	  auto order = _qin->pop();
	  insert_order(order);
	}

	for(;;) {
	  Transaction* ptx = nullptr;
	  auto ret = do_match(&ptx);
	  if(ret == 0 && ptx != nullptr) 
	    _qout->push(ptx);
	  else {
	    usleep(10*1000);
	    dot("*");
	    break;
	  }
	}
      }
      printf("MatchEngine::run exit!\n");
    }

    void set_queues(utils::Queue<Order*>* in, utils::Queue<Transaction*>* out)
    {
      _qin = in;
      _qout = out;
    }

    double market_rate()
    {
      return _marketRate;
    }
  private:

    bool is_seller(int from, int to)
    {
      return to == TOKEN_BTC;
    }
    
    int insert_order(Order* order)
    {
      if(is_seller(order->_from, order->_to))
	return _sellerOrderBook.insert(order);
      else
	return _buyerOrderBook.insert(order);
    }
  
    void update_market_rate(double rate)
    {
      static uint64_t totalcnt = 0;
      int cnt = 10;
    
      if(_lastRates.size() < cnt) 
	_lastRates.push_back(rate);
      else 
	_lastRates[totalcnt%cnt] = rate;
    
      cnt = _lastRates.size();
      double sum = 0;
    
      for(auto a : _lastRates)
	sum += a;
    
      totalcnt++;
    
      _marketRate = sum/cnt;

    }

    int do_match(TransactionPtr & ptx)
    {

      auto & book1 = _sellerOrderBook;
      auto & book2 = _buyerOrderBook;

      OrderPtr order;

      std::function<void()> order_erase;
      
      if(!book1._marketPriceOrderQueue.empty()) {
	order = book1._marketPriceOrderQueue.front();
	order_erase = [&]{ book1._marketPriceOrderQueue.pop(); };
      } else if(!book1._limitPriceOrderSetByRate.empty()) {
	auto pos = book1._limitPriceOrderSetByRate.begin();
	order = *pos;
	order_erase = [&, =pos]{ book1._limitPriceOrderSetByRate.erase(pos); }; //!!!
      } else {
	return 1;
      }

      {
	auto end = book2._marketPriceOrderSetByNum.end();
	auto pos = book2._marketPriceOrderSetByNum.find(order->_num);
      
	if(pos != end)  {
	  match_handler(order, *pos);
	  order_erase();
	  book2._marketPriceOrderSetByNum.erase(pos);
	  return 0;
	}
      }

      {
	auto end = book2._limitPriceOrderMapByNum.end();
	auto pos = book2._limitPriceOrderMapByNum.find(order->_num);

	if(pos != end) {
	  auto pos1 = book2.find_valid_order_by_rate(order->_rate, pos->second); //???
	  if(pos1 != pos->second->end()) {
	    match_handler(order, *pos1);
	    order_erase();
	    pos->second->erase(pos1);
	    return 0;
	  }
	}
      }


      {
	auto end = book2._marketPriceOrderSetByNum.end();
	auto pos = num_set_find_nearest(order->_num, book2._marketPriceOrderSetByNum); //???
					     
	if(pos != end)  {
	  match_handler(order, *pos);
	  order_erase();
	  book2._marketPriceOrderSetByNum.erase(pos);
	  return 0;
	}
      }

      {
	auto end = book2._limitPriceOrderMapByNum.end();
	auto pos = num_map_find_nearest(order->_num, book2._limitPriceOrderMapByNum);
	
	if(pos != end) {
	  auto pos1 = book2.find_valid_order_by_rate(order->_rate, pos->second); //???
	  if(pos1 != pos->second->end()) {
	    match_handler(order, *pos1);
	    order_erase();
	    pos->second->erase(pos1);
	    return 0;
	  }
	}
      }

      {
	auto end = book2._limitPriceOrderSetByRate.end();
	auto pos = book2._limitPriceOrderSetByRate.begin();

	if(pos != end) {
	  if(is_orders_match(order, *pos)) {
	    match_handler(order, *pos);
	    order_erase();
	    book2._limitPriceOrderSetByRate.erase(pos);
	    return 0;
	  }
	}
      }

      return 2;


      
      
      if(_sellerOrderBook._book.empty() || _buyerOrderBook._book.empty())
	return 1;
    
      auto sellerOrder = _sellerOrderBook._book.front();
      auto buyerOrder = _buyerOrderBook._book.front();
    
      if(sellerOrder->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE)
	sellerOrder->_rate = _marketRate;
      if(buyerOrder->_type == ORDER_TYPE_DELEGATE_BY_MARKET_PRICE)
	buyerOrder->_rate = _marketRate;

      if(buyerOrder->_rate < sellerOrder->_rate)
	return 2;

      double rate = _marketRate;

      if(_marketRate < sellerOrder->_rate)
	rate = sellerOrder->_rate;
      else if(_marketRate > buyerOrder->_rate)
	rate = buyerOrder->_rate;

      update_market_rate(rate);

      ptx = std::make_shared<Transaction>(sellerOrder, buyerOrder, rate, std::min(sellerOrder->_num, buyerOrder->_num));
      
      _sellerOrderBook._book.pop_front();
      _buyerOrderBook._book.pop_front();
    
      return 0;
    }

    utils::Queue<OrderPtr>* _qin{nullptr};
    utils::Queue<TransactionPtr>* _qout{nullptr};
    
    std::vector<double> _lastRates;
    double _marketRate = Configure::initMarketRate;
  
    OrderBook<OrderRateSet1> _sellerOrderBook{true};
    OrderBook<OrderRateSet2> _buyerOrderBook{false};
  };

} // namespace exchange

int main()
{
  volatile bool alive = true;
  exchange::MatchEngine engine;
  
  utils::Queue<exchange::Order*> qorder;
  utils::Queue<exchange::Transaction*> qtx;
  
  engine.set_queues(&qorder, &qtx);

  std::thread orderGenerator([&]{
      // from, to, type, rate, num, minNum, user, timeStamp

      sleep(1);

      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(new exchange::Order(0, 1, 1, 0.66, 10, 0, "alice3"));
      qorder.push(new exchange::Order(1, 0, 1, 0.44, 20, 0, "bob3"));
      
      sleep(1);
      
      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(new exchange::Order(0, 1, 1, 0.66, 30, 0, "alice4"));
      qorder.push(new exchange::Order(1, 0, 1, 0.65, 20, 0, "bob4"));
      
      sleep(1);

      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(new exchange::Order(0, 1, 1, 0.36, 30, 0, "alice5"));
      qorder.push(new exchange::Order(1, 0, 1, 0.35, 30, 0, "bob5"));

      sleep(1);

      printf("\nmarket rate:  %.8f\n", engine.market_rate());
      qorder.push(new exchange::Order(0, 1, 0, 0.00, 30, 0, "alice6"));
      qorder.push(new exchange::Order(1, 0, 0, 0.00, 40, 0, "bob6"));
      
    });
  
  std::thread matchProc(&exchange::MatchEngine::run, &engine, &alive);
  
  std::thread txDumpProc([&]{
      for(;;) {
	auto tx = qtx.pop();
	tx->dump();
      }
    });
  
  orderGenerator.join();
  matchProc.join();
  txDumpProc.join();
  
  return 0;
}
