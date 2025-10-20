enum IFF_Container_Type
{
	IFF_Container_Type_CAT,
	IFF_Container_Type_LIST,
	IFF_Container_Type_FORM
};

struct IFF_Container_Data_Cat
{
	struct VPS_List children;
};
struct IFF_Container_Data_List
{
	struct VPS_List children;
	struct IFF_Tag content_type;
	struct VPS_List props;
};
struct IFF_Container_Data_Form
{
	struct VPS_List children;
	struct IFF_Tag content_type;
	struct VPS_List chunks;
};
union IFF_Container_Data
{
	struct IFF_Container_Data_List list;
	struct IFF_Container_Data_Cat cat;
	struct IFF_Container_Data_Form form;
};

struct IFF_Container
{
	enum IFF_Container_Type type;
	VPS_TYPE_SIZE size;

	union IFF_Container_Data data;
};
