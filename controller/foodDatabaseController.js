const supabase = require('../dbConnection');

exports.searchFood = async (req, res) => {
    try {
        const { query } = req.query;
        if (!query) return res.status(400).json({ success: false, error: 'query param required' });

        const candidateTables = ['ingredients', 'food_items', 'fooditem', 'food_data', 'foods', 'fooddata'];

        for (const table of candidateTables) {
            try {
                const { data, error } = await supabase
                    .from(table)
                    .select('*')
                    .ilike('name', `%${query}%`)
                    .limit(20);

                if (error) {
                    continue;
                }

                if (Array.isArray(data)) {
                    return res.status(200).json({ success: true, data: data || [] });
                }
            } catch (err) {
                continue;
            }
        }

        res.status(200).json({ success: true, data: [] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
};
