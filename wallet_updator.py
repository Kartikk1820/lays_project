from database import *


# Initialize the scheduler



def update_wallets_rate():


    all_users = get_all_user_id()

    for user_id in all_users:
        all_active_scheme = get_active_schemes_for_user(user_id)
        
        income_rate = 0
        for scheme in all_active_scheme:
            rate = scheme["daily_rate"]
            initial_deposit = scheme["initial_deposit"]
            income_rate += rate * initial_deposit


            time_left = get_time_left(scheme["scheme_id"],user_id) 
            time_left -= 1

            update_scheme_time_left(scheme["scheme_id"] , time_left)

        update_wallet_income_rate(user_id , income_rate)
    
    for user_id in all_users:    
        income_rate = 0
        # Get level 1 team
        level_1_team = get_level_1_team(user_id)
        if not level_1_team:
            continue


        level_1_ids = [user['id'] for user in level_1_team]

        for team_user_id in level_1_ids:
            print(team_user_id)
            team_user_wallet_income = get_wallet_income_rate(team_user_id)
            income_rate += team_user_wallet_income * 0.32
        
        update_wallet_income_rate(user_id , income_rate)
    

def update_wallets_periodically():
    update_wallets_rate()
    for user_id in get_all_user_id():
        
        income_rate = get_wallet_income_rate(user_id)

        record_payment(payer_id="scheme" , receiver_id=user_id , amount=income_rate , is_admin=True)



def run_worker():
    import logging
    import time
    from apscheduler.schedulers.background import BackgroundScheduler

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("scheduler.log"),  # Log to a file
            logging.StreamHandler()  # Log to console
        ]
    )
    
    logging.getLogger('apscheduler').setLevel(logging.DEBUG)

    scheduler = BackgroundScheduler()

    try:
        # Schedule the job
        scheduler.add_job(update_wallets_periodically, 'interval', seconds=5)
        scheduler.start()  # Start the scheduler
        logging.info("Scheduler started.")

        # Keep the script running
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        if scheduler.running:
            logging.info("Shutting down the scheduler.")
            scheduler.shutdown()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")



if __name__ == '__main__':
    update_wallets_periodically()
    # run_worker()